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
package ghidra.app.plugin.cheri.datatype;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

import ghidra.util.DataConverter;

/**
 * A data type whose value is a particular Dwarf decoder.
 */
public class GotCapabilityMetadataDataType extends BuiltIn {

	public final static GotCapabilityMetadataDataType dataType = new GotCapabilityMetadataDataType();

	/**
	 * Data type whose value indicates the type of Dwarf encoding used for other data.
	 */
	public GotCapabilityMetadataDataType() {
		this(null);
	}

	/**
	 * Data type whose value indicates the type of Dwarf encoding used for other data.
	 * @param dtm the data type manager associated with this data type.
	 */
	public GotCapabilityMetadataDataType(DataTypeManager dtm) {
		super(CategoryPath.ROOT, "gotcapmeta", dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new GotCapabilityMetadataDataType(dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "gotcapmeta";
	}

	@Override
	public int getLength() {
		return 8;
	}

	@Override
	public String getDescription() {
		return "GOT capability metadata";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return getRepresentation(buf, settings, length);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
        final int lengthFieldSize = 7;
        final int permsFieldSize = 1;

		byte[] lengthBytes = new byte[lengthFieldSize];
        byte[] permsBytes = new byte[permsFieldSize];
		if (buf.getBytes(lengthBytes, 0) != lengthFieldSize) {
			return "??";
		}
		if (buf.getBytes(permsBytes, 7) != permsFieldSize) { // ?
			return "??";
		}
		DataConverter converter = DataConverter.getInstance(buf.isBigEndian());
		Long capLength = converter.getValue(lengthBytes, lengthFieldSize);
        Long capPermsValue = converter.getValue(permsBytes, permsFieldSize);
		String capPerms = "UNKNOWN";
		if (capPermsValue.equals(0x1L)) {
			capPerms = "R";
		} else if (capPermsValue.equals(0x2L)) {
			capPerms = "RW";
		} else if (capPermsValue.equals(0x4L)) {
			capPerms = "X";
		}
		return "CapLength: " + capLength.toString() + ", " +
				"CapPerms: " + capPerms;
	}
}
