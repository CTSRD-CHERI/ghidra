/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf.extend;

import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.cmd.refs.RemoveReferenceCmd;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.plugin.cheri.datatype.GotCapabilityMetadataDataType;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class AARCH64_ElfExtension extends ElfExtension {

	// Elf Program Header Extensions
	public static final ElfProgramHeaderType PT_AARCH64_ARCHEXT =
		new ElfProgramHeaderType(0x70000000, "PT_AARCH64_ARCHEXT", "AARCH64 extension");

	// Elf Section Header Extensions
	public static final ElfSectionHeaderType SHT_AARCH64_ATTRIBUTES =
		new ElfSectionHeaderType(0x70000003, "SHT_AARCH64_ATTRIBUTES", "Attribute section");

	// Section header flags
	private static final int SHF_ENTRYSECT = 0x10000000; // section contains entry point
	private static final int SHF_COMDEF = 0x80000000; // section may be multiply defined

	// When PLT head is known and named sections are missing this label will be placed at head of PLT
	private static final String PLT_HEAD_SYMBOL_NAME = "__PLT_HEAD";

	private ElfDefaultGotPltMarkup gotPltMarkup;

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_AARCH64;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"AARCH64".equals(language.getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_AARCH64";
	}

	@Override
	public void processGotPlt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {
		Program program = elfLoadHelper.getProgram();
		if (program.getRegister("C64") == null) {
			super.processGotPlt(elfLoadHelper, monitor);
		} else {
			// C64 GOT entries contain an additional 64-bits for capability metadata
			// likewise for GOTPLT entries
			gotPltMarkup = new ElfDefaultGotPltMarkup(elfLoadHelper); // reuse some functions
			if (elfLoadHelper.getElfHeader().getSectionHeaderCount() == 0) {
				processMorelloDynamicPLTGOT(elfLoadHelper, ElfDynamicType.DT_PLTGOT, ElfDynamicType.DT_JMPREL, monitor);
			}
			else {
				processGOTSections(elfLoadHelper, monitor);
				processPLTSection(elfLoadHelper, monitor);
			}
		}
	}

	@Override
	public Address creatingFunction(ElfLoadHelper elfLoadHelper, Address functionAddress) {
		Program program = elfLoadHelper.getProgram();
		if ((functionAddress.getOffset() & 1) != 0) {
			// check if C64 is available
			if (program.getRegister("C64") == null) {
				Msg.error(AARCH64_ElfExtension.class, "Invalid function address");
			} else {
				functionAddress = functionAddress.previous(); // align address
			}
		}
		return functionAddress;
	}

	@Override
	public Address evaluateElfSymbol(ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol,
			Address address, boolean isExternal) {

		if (isExternal) {
			return address;
		}

		String symName = elfSymbol.getNameAsString();
		if (StringUtils.isBlank(symName)) {
			return address;
		}

		if ("$x".equals(symName) || symName.startsWith("$x.")) {
			// is A64 code
			elfLoadHelper.markAsCode(address);

			// do not retain $x symbols in program due to potential function/thunk naming interference
			elfLoadHelper.setElfSymbolAddress(elfSymbol, address);
			return null;
		}
		else if ("$c".equals(symName) || symName.startsWith("$c.")) {
			// is C64 code
			elfLoadHelper.markAsCode(address);

			// do not retain $c symbols in program due to potential function/thunk naming interference
			elfLoadHelper.setElfSymbolAddress(elfSymbol, address);
			return null;
		}
		else if ("$d".equals(symName) || symName.startsWith("$d.")) {
			// is data, need to protect as data
			elfLoadHelper.createUndefinedData(address, (int) elfSymbol.getSize());

			// do not retain $d symbols in program due to excessive duplicate symbols
			elfLoadHelper.setElfSymbolAddress(elfSymbol, address);
			return null;
		}

		return address;
	}

	private static class PltGotSymbol implements Comparable<PltGotSymbol> {
		final ElfSymbol elfSymbol;
		final long offset;

		PltGotSymbol(ElfSymbol elfSymbol, long offset) {
			this.elfSymbol = elfSymbol;
			this.offset = offset;
		}

		@Override
		public int compareTo(PltGotSymbol o) {
			return Long.compareUnsigned(offset, o.offset);
		}
	}

	/**
	 * Process all GOT sections based upon blocks whose names begin with .got
	 * @param monitor task monitor
	 * @throws CancelledException thrown if task cancelled
	 */
	private void processGOTSections(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {
		// look for .got section blocks
		Program program = elfLoadHelper.getProgram();
		Memory memory = program.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();
		for (MemoryBlock gotBlock : blocks) {
			monitor.checkCancelled();

			if (!gotBlock.getName().startsWith(ElfSectionHeaderConstants.dot_got) ||
				!gotBlock.isInitialized()) {
				continue;
			}

			// Assume the .got section is read_only.  This is not true, but it helps with analysis
			gotBlock.setWrite(false);
			// fixup for Morello
			processGOT(elfLoadHelper, gotBlock.getStart(), gotBlock.getEnd().add(16), monitor);
		}
	}

	private void processPLTSection(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		// TODO: May want to consider using analysis to fully disassemble PLT, we only 
		// really need to migrate external symbols contained within the PLT

		ElfHeader elf = elfLoadHelper.getElfHeader();
		Program program = elfLoadHelper.getProgram();
		Memory memory = program.getMemory();
		
		// FIXME: Code needs help ... bad assumption about PLT head size (e.g., 16)
		int assumedPltHeadSize = 16;

		if (elf.isRelocatable()) {
			return; //relocatable files do not have .PLT sections
		}

		MemoryBlock pltBlock = memory.getBlock(ElfSectionHeaderConstants.dot_plt);
		// TODO: This is a band-aid since there are many PLT implementations and this assumes only one.
		if (pltBlock == null || !pltBlock.isExecute() || !pltBlock.isInitialized() ||
			pltBlock.getSize() <= assumedPltHeadSize) {
			return;
		}

		int skipPointers = assumedPltHeadSize;

		// ARM, AARCH64 and others may not store pointers at start of .plt
		if (elf.e_machine() == ElfConstants.EM_ARM || elf.e_machine() == ElfConstants.EM_AARCH64) {
			skipPointers = 0; // disassemble entire PLT
		}

		// Process PLT section
		Address minAddress = pltBlock.getStart().add(skipPointers);
		Address maxAddress = pltBlock.getEnd();
		gotPltMarkup.processLinkageTable(ElfSectionHeaderConstants.dot_plt, minAddress, maxAddress, monitor);
	}

	// When scanning PLT for symbols the min/max entry size are used to control the search
	private static final int MAX_SUPPORTED_PLT_ENTRY_SIZE = 32;
	private static final int MIN_SUPPORTED_PLT_ENTRY_SIZE = 8;

	// When scanning PLT for symbol spacing this is the threashold used to stop the search
	// when the same spacing size is detected in an attempt to identify the PLT entry size
	private static final int PLT_SYMBOL_SAMPLE_COUNT_THRESHOLD = 10;

	/**
	 * Process GOT and associated PLT based upon specified dynamic table entries.
	 * The primary goal is to identify the bounds of the GOT and PLT and process
	 * any external symbols which may be defined within the PLT. Processing of PLT
	 * is only critical if it contains external symbols which must be processed, otherwise
	 * they will likely resolve adequately during subsequent analysis.
	 * @param pltGotType dynamic type for dynamic PLTGOT lookup (identifies dynamic PLTGOT)
	 * @param pltGotRelType dynamic type for associated dynamic JMPREL lookup (identifies dynamic PLTGOT relocation table)
	 * @param monitor task monitor
	 * @throws CancelledException thrown if task cancelled
	 */
	private void processMorelloDynamicPLTGOT(ElfLoadHelper elfLoadHelper, ElfDynamicType pltGotType, 			
			ElfDynamicType pltGotRelType, TaskMonitor monitor) throws CancelledException {

		ElfHeader elf = elfLoadHelper.getElfHeader();
		Program program = elfLoadHelper.getProgram();

		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable == null || !dynamicTable.containsDynamicValue(pltGotType) ||
			!dynamicTable.containsDynamicValue(pltGotRelType)) {
			return;
		}

		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		long imageBaseAdj = elfLoadHelper.getImageBaseWordAdjustmentOffset();

		try {
			long relocTableAddr =
				elf.adjustAddressForPrelink(dynamicTable.getDynamicValue(pltGotRelType));

			ElfProgramHeader relocTableLoadHeader =
				elf.getProgramLoadHeaderContaining(relocTableAddr);
			if (relocTableLoadHeader == null || relocTableLoadHeader.isInvalidOffset()) {
				return;
			}
			long relocTableOffset = relocTableLoadHeader.getOffset(relocTableAddr);
			ElfRelocationTable relocationTable = elf.getRelocationTableAtOffset(relocTableOffset);
			if (relocationTable == null) {
				return;
			}

			// External dynamic symbol entries in the GOT, if any, will be placed
			// after any local symbol entries.  Local entries are assumed to have original 
			// bytes of zero, whereas non-local entries will refer to the PLT

			// While the dynamic value for pltGotType (e.g., DT_PLTGOT) identifies the start of 
			// dynamic GOT table it does not specify its length.  The associated relocation
			// table, identified by the dynamic value for pltGotRelType, will have a relocation
			// record for each PLT entry linked via the GOT.  The number of relocations matches
			// the number of PLT entries and the one with the greatest offset correspionds
			// to the last GOT entry.  Unfortuntely, the length of each PLT entry and initial
			// PLT head is unknown.  If the binary has not placed external symbols within the PLT
			// processing and disassembly of the PLT may be skipped.

			long pltgot = elf.adjustAddressForPrelink(
				dynamicTable.getDynamicValue(pltGotType));
			Address gotStart = defaultSpace.getAddress(pltgot + imageBaseAdj);

			ElfRelocation[] relocations = relocationTable.getRelocations();
			ElfSymbolTable associatedSymbolTable = relocationTable.getAssociatedSymbolTable();
			if (associatedSymbolTable == null) {
				return;
			}

			// Create ordered list of PLTGOT symbols based upon offset with GOT.
			// It assumed that the PLT entry sequence will match this list.
			ElfSymbol[] symbols = associatedSymbolTable.getSymbols();
			List<PltGotSymbol> pltGotSymbols = new ArrayList<>();
			for (ElfRelocation reloc : relocations) {
				pltGotSymbols
						.add(new PltGotSymbol(symbols[reloc.getSymbolIndex()], reloc.getOffset()));
			}
			Collections.sort(pltGotSymbols);

			// Identify end of GOT table based upon relocation offsets
			// Add 8 bits for capability metadata in Morello
			long maxGotOffset = pltGotSymbols.get(pltGotSymbols.size() - 1).offset + 8;
			Address gotEnd = defaultSpace.getAddress(maxGotOffset + imageBaseAdj);

			processGOT(elfLoadHelper, gotStart, gotEnd, monitor);

			//
			// Examine the first two GOT entries which correspond to the relocations (i.e., pltGotSymbols).
			// An adjusted address from the original bytes is computed.  These will point into the PLT.  
			// These two pointers will either refer to the same address (i.e., PLT head) or different 
			// addresses which correspond to the first two PLT entries.  While likely offcut into each PLT 
			// entry, the differing PLT addresses can be used to identify the PLT entry size/spacing but 
			// not the top of PLT.  If symbols are present within the PLT for each entry, they may 
			// be used to identify the PLT entry size/spacing and will be converted to external symbols.
			// 

			long pltEntryCount = pltGotSymbols.size();

			// Get original bytes, converted to addresses, for first two PLT/GOT symbols
			Address pltAddr1 = null;
			Address pltAddr2 = null;
			for (PltGotSymbol pltGotSym : pltGotSymbols) {
				Address gotEntryAddr = defaultSpace.getAddress(pltGotSym.offset + imageBaseAdj);
				long originalGotEntry = elfLoadHelper.getOriginalValue(gotEntryAddr, true);
				if (originalGotEntry == 0) {
					return; // unexpected original bytes for PLTGOT entry - skip PLT processing
				}
				if (pltAddr1 == null) {
					pltAddr1 = defaultSpace.getAddress(originalGotEntry + imageBaseAdj);
				}
				else {
					pltAddr2 = defaultSpace.getAddress(originalGotEntry + imageBaseAdj);
					break;
				}
			}
			if (pltAddr2 == null) {
				return; // unable to find two GOT entries which refer to PLT - skip PLT processing
			}

			// NOTE: This approach assumes that all PLT entries have the same structure (i.e., instruction sequence)
			long pltSpacing = pltAddr2.subtract(pltAddr1);
			if (pltSpacing < 0 || pltSpacing > MAX_SUPPORTED_PLT_ENTRY_SIZE ||
				(pltSpacing % 2) != 0) {
				return; // unsupported PLT entry size - skip PLT processing
			}

			Address minSymbolSearchAddress;
			long symbolSearchSpacing; // nominal PLT entry size for computing maxSymbolSearchAddress

			Address firstPltEntryAddr = null; // may be offcut within first PLT entry

			if (pltSpacing == 0) { // Entries have same original bytes which refer to PLT head
				Function pltHeadFunc = elfLoadHelper.createOneByteFunction(null, pltAddr1, false);
				if (pltHeadFunc.getSymbol().getSource() == SourceType.DEFAULT) {
					try {
						pltHeadFunc.setName(PLT_HEAD_SYMBOL_NAME, SourceType.ANALYSIS);
					}
					catch (DuplicateNameException | InvalidInputException e) {
						// Ignore - unexpected
					}
				}

				// PLT spacing is not known.  pltAddr1 is PLT head
				minSymbolSearchAddress = pltAddr1.next();

				// Use conservative PLT entry size when computing address limit for PLT symbol search.
				// For a PLT with an actual entry size of 16 this will reduce the scan to less than half 
				// of the PLT.  This should only present an issue for very small PLTs or those 
				// with sparsely placed symbols.
				symbolSearchSpacing = MIN_SUPPORTED_PLT_ENTRY_SIZE;
			}
			else {
				// PLT spacing is known, but start of entry and head is not known.  pltAddr1 points to middle of first PLT entry (not head).
				firstPltEntryAddr = pltAddr1;
				minSymbolSearchAddress = pltAddr1.subtract(pltSpacing - 1); // try to avoid picking up symbol which may be at head
				symbolSearchSpacing = pltSpacing;
			}

			// Attempt to find symbols located within the PLT.
			Address maxSymbolSearchAddress =
				minSymbolSearchAddress.add(pltEntryCount * symbolSearchSpacing);

			// Scan symbols within PLT; helps to identify start of first entry and PLT entry size/spacing if unknown
			Symbol firstSymbol = null;
			Symbol lastSymbol = null;
			long discoveredPltSpacing = Long.MAX_VALUE;
			Map<Long, Integer> spacingCounts = new HashMap<>();
			for (Symbol sym : elfLoadHelper.getProgram()
					.getSymbolTable()
					.getSymbolIterator(minSymbolSearchAddress, true)) {
				if (sym.getSource() == SourceType.DEFAULT) {
					continue;
				}
				Address addr = sym.getAddress();
				if (addr.compareTo(maxSymbolSearchAddress) > 0) {
					break;
				}
				if (firstSymbol == null) {
					firstSymbol = sym;
				}
				if (pltSpacing == 0) {
					// Collect spacing samples if PLT spacing is unknown
					if (lastSymbol != null) {
						long spacing = addr.subtract(lastSymbol.getAddress());
						if (spacing > MAX_SUPPORTED_PLT_ENTRY_SIZE) {
							lastSymbol = null; // reset on large symbol spacing
							continue;
						}
						int count =
							spacingCounts.compute(spacing, (k, v) -> (v == null) ? 1 : v + 1);
						discoveredPltSpacing = Math.min(discoveredPltSpacing, spacing);
						if (count == PLT_SYMBOL_SAMPLE_COUNT_THRESHOLD) {
							break; // stop on 10 occurances of the same spacing (rather arbitrary sample limit)
						}
					}
					lastSymbol = sym;
				}
			}

			if (pltSpacing == 0) {
				if (discoveredPltSpacing == Long.MAX_VALUE ||
					spacingCounts.get(discoveredPltSpacing) == 1) { // NOTE: required number of symbol-spacing samples could be increased from 1
					return; // PLT spacing not determined / too large or insufficient PLT symbols - skip PLT processing
				}
				pltSpacing = discoveredPltSpacing;
			}

			if (firstSymbol != null) {
				// use PLT symbol if found to identify start of first PLT entry
				int firstSymbolEntryIndex = -1;
				Address firstSymbolAddr = firstSymbol.getAddress();
				int entryIndex = 0;
				for (PltGotSymbol entrySymbol : pltGotSymbols) {
					if (firstSymbolAddr
							.equals(elfLoadHelper.getElfSymbolAddress(entrySymbol.elfSymbol))) {
						firstSymbolEntryIndex = entryIndex;
						break;
					}
					++entryIndex;
				}
				if (firstSymbolEntryIndex >= 0) {
					firstPltEntryAddr = firstSymbolAddr;
					if (firstSymbolEntryIndex > 0) {
						firstPltEntryAddr =
							firstPltEntryAddr.subtract(firstSymbolEntryIndex * pltSpacing);
					}
				}
			}

			if (firstPltEntryAddr == null) {
				return; // failed to identify first PLT entry - skip PLT processing
			}

			Address pltEnd = firstPltEntryAddr.add(pltSpacing * (pltEntryCount - 1));
			gotPltMarkup.processLinkageTable("PLT", firstPltEntryAddr, pltEnd, monitor);
		}
		catch (Exception e) {
			String msg = "Failed to process " + pltGotType + ": " + e.getMessage();
			elfLoadHelper.log(msg);
			Msg.error(this, msg, e);
		}
	}

	/**
	 * Mark-up all GOT entries as pointers within the memory range gotStart to
	 * gotEnd.
	 * @param gotStart address for start of GOT
	 * @param gotEnd address for end of GOT
	 * @param monitor task monitor
	 * @throws CancelledException thrown if task cancelled
	 */
	private void processGOT(ElfLoadHelper elfLoadHelper,
			Address gotStart, Address gotEnd, TaskMonitor monitor)
			throws CancelledException {
		
		ElfHeader elf = elfLoadHelper.getElfHeader();
		Program program = elfLoadHelper.getProgram();
		Memory memory = program.getMemory();

		// Bail if GOT was previously marked-up or not within initialized memory
		MemoryBlock block = memory.getBlock(gotStart);
		if (block == null || !block.isInitialized()) {
			return; // unsupported memory region - skip GOT processing
		}
		Data data = program.getListing().getDataAt(gotStart);
		if (data == null || !Undefined.isUndefined(data.getDataType())) {
			return; // evidence of prior markup - skip GOT processing
		}

		// Fixup first GOT entry which frequently refers to _DYNAMIC but generally lacks relocation (e.g. .got.plt)
		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		long imageBaseAdj = elfLoadHelper.getImageBaseWordAdjustmentOffset();
		if (dynamicTable != null && imageBaseAdj != 0) {
			try {
				long entry1Value = elfLoadHelper.getOriginalValue(gotStart, false);
				if (entry1Value == dynamicTable.getAddressOffset()) {
					// TODO: record artificial relative relocation for reversion/export concerns
					entry1Value += imageBaseAdj; // adjust first entry value
					if (elf.is64Bit()) {
						elfLoadHelper.addArtificialRelocTableEntry(gotStart, 8);
						memory.setLong(gotStart, entry1Value);
					}
					else {
						elfLoadHelper.addArtificialRelocTableEntry(gotStart, 4);
						memory.setInt(gotStart, (int) entry1Value);
					}
				}
			}
			catch (Exception e) {
				String msg =
					"Failed to process first GOT entry at " + gotStart + ": " + e.getMessage();
				elfLoadHelper.log(msg);
				Msg.error(this, msg, e);
			}
		}

		boolean imageBaseAlreadySet = elf.isPreLinked();

		try {
			int pointerSize = program.getDataTypeManager().getDataOrganization().getPointerSize();
			Address newImageBase = null;
			Address nextGotAddr = gotStart;
			while (gotEnd.subtract(nextGotAddr) >= pointerSize) {

				// data = createPointer(elfLoadHelper, nextGotAddr, true);
				data = createPointerWithMetadata(elfLoadHelper, nextGotAddr, true);
				if (data == null) {
					break;
				}

				try {
					nextGotAddr = nextGotAddr.add(16);
				}
				catch (AddressOutOfBoundsException e) {
					break; // no more room
				}
			}
		}
		catch (Exception e) {
			String msg = "Failed to process GOT at " + gotStart + ": " + e.getMessage();
			elfLoadHelper.log(msg);
			Msg.error(this, msg, e);
		}
	}

	private Data createPointerWithMetadata(ElfLoadHelper elfLoadHelper, Address addr, boolean keepRefWhenValid)
			throws CodeUnitInsertionException {
		
		ElfHeader elf = elfLoadHelper.getElfHeader();
		Program program = elfLoadHelper.getProgram();
		Memory memory = program.getMemory();
		Listing listing = program.getListing();

		MemoryBlock block = memory.getBlock(addr);
		if (block == null || !block.isInitialized()) {
			return null;
		}
		int pointerSize = program.getDataTypeManager().getDataOrganization().getPointerSize();
		Pointer ptrDT = PointerDataType.dataType.clone(program.getDataTypeManager());
		if (elf.is32Bit() && pointerSize != 4) {
			ptrDT = Pointer32DataType.dataType;
		}
		else if (elf.is64Bit() && pointerSize != 8) {
			ptrDT = Pointer64DataType.dataType;
		}
		Data data = listing.getDataAt(addr);
		if (data == null || !ptrDT.isEquivalent(data.getDataType())) {
			if (data != null) {
				listing.clearCodeUnits(addr, addr.add(pointerSize - 1), false);
			}
			data = listing.createData(addr, ptrDT);
		}
		if (keepRefWhenValid && gotPltMarkup.isValidPointer(data)) {
			// FIXME: check if it's null (shouldn't be possible)
			gotPltMarkup.setConstant(data);
		}
		else {
			removeMemRefs(data);
		}
		// parse the length and perms
		Data metadata = listing.getDataAt(addr.add(pointerSize));  // TODO: exception handling
		if (metadata == null || !GotCapabilityMetadataDataType.dataType.isEquivalent(metadata.getDataType())) {
			if (metadata != null) {
				listing.clearCodeUnits(addr.add(pointerSize), addr.add(pointerSize*2 - 1), false);
			}
			metadata = listing.createData(addr.add(pointerSize), GotCapabilityMetadataDataType.dataType);
		}

		return data;
	}

	private Data createPointer(ElfLoadHelper elfLoadHelper, Address addr, boolean keepRefWhenValid)
			throws CodeUnitInsertionException {

		ElfHeader elf = elfLoadHelper.getElfHeader();
		Program program = elfLoadHelper.getProgram();
		Memory memory = program.getMemory();
		Listing listing = program.getListing();

		MemoryBlock block = memory.getBlock(addr);
		if (block == null || !block.isInitialized()) {
			return null;
		}
		int pointerSize = program.getDataTypeManager().getDataOrganization().getPointerSize();
		Pointer pointer = PointerDataType.dataType.clone(program.getDataTypeManager());
		if (elf.is32Bit() && pointerSize != 4) {
			pointer = Pointer32DataType.dataType;
		}
		else if (elf.is64Bit() && pointerSize != 8) {
			pointer = Pointer64DataType.dataType;
		}
		Data data = listing.getDataAt(addr);
		if (data == null || !pointer.isEquivalent(data.getDataType())) {
			if (data != null) {
				listing.clearCodeUnits(addr, addr.add(pointerSize - 1), false);
			}
			data = listing.createData(addr, pointer);
		}
		if (keepRefWhenValid && gotPltMarkup.isValidPointer(data)) {
			// FIXME: check if it's null (shouldn't be possible)
			gotPltMarkup.setConstant(data);
		}
		else {
			removeMemRefs(data);
		}
		return data;
	}

	private void removeMemRefs(Data data) {
		if (data != null) {
			Reference[] refs = data.getValueReferences();
			for (Reference ref : refs) {
				RemoveReferenceCmd cmd = new RemoveReferenceCmd(ref);
				cmd.applyTo(data.getProgram());
			}
		}
	}
}
