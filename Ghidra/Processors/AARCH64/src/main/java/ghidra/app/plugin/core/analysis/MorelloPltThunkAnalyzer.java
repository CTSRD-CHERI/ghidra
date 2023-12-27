package ghidra.app.plugin.core.analysis;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;

import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MorelloPltThunkAnalyzer extends AbstractAnalyzer {
	
	private static final String NAME = "Morello C64 ELF PLT Thunks";
	private static final String DESCRIPTION = "Create AARCH64 C64 ELF PLT thunk functions";
	private static final String PROCESSOR_NAME = "AARCH64";

	private static final String MORELLO_COMPILER_SPEC_ID = "clang-morello";
	private static final String PLT_THUNK_PATTERN_FILE = "morello-pltThunks.xml";
	
	private static boolean patternLoadFailed;
	private static ArrayList<Pattern> leThunkPatterns;
	private static int maxPatternLength;
	
	private Register c17Reg;
	
	public MorelloPltThunkAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER); // assumes ELF Loader disassembled PLT section
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
	}
	
	@Override
	public boolean canAnalyze(Program program) {
		Language language = program.getLanguage();
		CompilerSpec compilerSpec = program.getCompilerSpec();
		if (PROCESSOR_NAME.equals(language.getProcessor().toString()) &&
				MORELLO_COMPILER_SPEC_ID.equals(compilerSpec.getCompilerSpecID().getIdAsString()) &&
				patternsLoaded(language.isBigEndian())) {
			c17Reg = program.getRegister("c17");
			return c17Reg != null;
		}
		return false;
	}

	private static synchronized boolean patternsLoaded(boolean bigEndian) {
		if (patternLoadFailed) {
			return false;
		}
		if (leThunkPatterns != null) {
			return true;
		}
		
		try {
			ResourceFile patternFile = Application.getModuleDataFile(PLT_THUNK_PATTERN_FILE);
			
			leThunkPatterns = new ArrayList<>();
			Pattern.readPatterns(patternFile, leThunkPatterns, null);
			
			maxPatternLength = 0;
			for (Pattern pattern : leThunkPatterns) {
				int len = pattern.getSize();
				if ((len % 4) != 0) {
					throw new SAXException("pattern must contain multiple of 4-bytes");
				}
				if (len > maxPatternLength) {
					maxPatternLength = len;
				}
			}
			
		} catch (FileNotFoundException e) {
			Msg.error(MorelloPltThunkAnalyzer.class, "Morello resource file not found: " + PLT_THUNK_PATTERN_FILE);
			patternLoadFailed = true;
			return false;
		} catch (SAXException | IOException e) {
			Msg.error(MorelloPltThunkAnalyzer.class, "Failed to parse byte pattern file: " + PLT_THUNK_PATTERN_FILE, e);
			patternLoadFailed = true;
			return false;
		}
		
		return true;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(".plt");
		if (block == null) {
			return true;
		}
		
		set = set.intersectRange(block.getStart(), block.getEnd());
		set = removeFunctionBodies(program, set, monitor);
		if (set.isEmpty()) {
			return true;
		}

		SequenceSearchState sequenceSearchState = SequenceSearchState.buildStateMachine(
				leThunkPatterns);
		
		monitor.setIndeterminate(true);
		monitor.setProgress(0);
		
		ArrayList<Match> matches = new ArrayList<>();
		
		try {
			for (AddressRange range : set.getAddressRanges()) {
				
				byte[] bytes = new byte[(int)range.getLength()];
				if (block.getBytes(range.getMinAddress(), bytes, 0, bytes.length) != bytes.length) {
					log.appendMsg("Expected initialized .plt section block");
					return false;
				}
				
				matches.clear();
				sequenceSearchState.apply(bytes, matches);
				
				for (Match match : matches) {
					Address addr = range.getMinAddress().add(match.getMarkOffset());
					analyzePltThunk(program, addr, match.getSequenceSize(), monitor);
				}
				
			}
		} catch (MemoryAccessException | AddressOutOfBoundsException e) {
			log.appendMsg("Expected initialized .plt section block: " + e.getMessage());
		}
		
		return true;
	}

	private AddressSetView removeFunctionBodies(Program program, AddressSetView set, TaskMonitor monitor) throws CancelledException {
		if (set.isEmpty()) {
			return set;
		}
		// Only processing importer disassembly not yet claimed by function bodies
		for (Function f : program.getFunctionManager().getFunctions(set, true)) {
			monitor.checkCancelled();
			set = set.subtract(f.getBody());
		}
		return set;
	}

	private void analyzePltThunk(Program program, Address entryAddr, int thunkSize, TaskMonitor monitor) 
			throws CancelledException {
		
		SymbolicPropogator symEval = new SymbolicPropogator(program);
		symEval.setParamRefCheck(false);
		symEval.setReturnRefCheck(false);
		symEval.setStoredRefCheck(false);
		
		AddressSet thunkBody = new AddressSet(entryAddr, entryAddr.add(thunkSize - 1));
		
		ContextEvaluator eval = new ContextEvaluatorAdapter() {

			@Override
			public boolean followFalseConditionalBranches() {
				return false; // should never happen - just in case
			}
			
			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop, Address address,
					int size, DataType dataType, RefType refType) {
				return true;
			}
			
			@Override
			public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
				
				// We only handle indirect branch through c17 register
				if (!"br".equals(instruction.getMnemonicString()) || !c17Reg.equals(instruction.getRegister(0))) {
					return true;
				}
				
				// Change br flow to call-return
				instruction.setFlowOverride(FlowOverride.CALL_RETURN);
				
				// FIXME: for now, just ignore capability metadata
				RegisterValue x17Value = context.getRegisterValue(program.getRegister("x17"));
				if (x17Value != null && x17Value.hasValue()) {
					Address destAddr = entryAddr.getNewAddress(x17Value.getUnsignedValue().longValue());
					Function thunkedFunction = createDestinationFunction(program, destAddr, instruction.getAddress(),
							monitor);
					if (thunkedFunction != null) {
						CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(entryAddr, thunkBody,
								thunkedFunction.getEntryPoint());
						cmd.applyTo(program);
					}
				}
				
				return true;
			}
			
			@Override
			public boolean allowAccess(VarnodeContext context, Address address) {
				return true;
			}
		};
		
		symEval.flowConstants(entryAddr, thunkBody, eval, false, monitor);
	}

	private Function createDestinationFunction(Program program, Address addr, Address flowFromAddr, TaskMonitor monitor) {

		Listing listing = program.getListing();
		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		
		if (!program.getMemory().contains(addr)) {
			bookmarkMgr.setBookmark(flowFromAddr, BookmarkType.ERROR, "Bad Reference", "No memory for PLT Thunk destination at " + addr);
			return null;
		}
		
		Function function = listing.getFunctionAt(addr);
		if (function != null) {
			return function;
		}
		
		CodeUnit cu = listing.getCodeUnitContaining(addr);
		if (cu == null) {
			throw new AssertException("expected code unit in memory");
		}
		if (!addr.equals(cu.getMinAddress())) {
			bookmarkMgr.setBookmark(cu.getMinAddress(), BookmarkType.ERROR, "Code Unit Conflict", 
					"Expected function entry at " + addr + " referenced by PLT Thunk at " + flowFromAddr);
			return null;
		}
		if (cu instanceof Data) {
			Data d = (Data)cu;
			if (d.isDefined()) {
				bookmarkMgr.setBookmark(addr, BookmarkType.ERROR, "Code Unit Conflict", "Expected function entry referenced by PLT Thunk at " + flowFromAddr);
				return null;
			}
			DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
			if (!cmd.applyTo(program, monitor)) {
				return null;
			}
		}
		
		CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
		if (cmd.applyTo(program, monitor)) {
			return cmd.getFunction();
		}
		return null;
	}

}
