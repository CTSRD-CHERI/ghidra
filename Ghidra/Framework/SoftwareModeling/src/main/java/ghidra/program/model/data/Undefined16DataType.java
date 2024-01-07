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
package ghidra.program.model.data;

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.StringFormat;
import ghidra.util.classfinder.*;

/**
 * Provides an implementation of an 16-byte dataType that has not been defined yet as a
 * particular type of data in the program.
 */
public class Undefined16DataType extends Undefined {
	static {
		ClassTranslator.put("ghidra.program.model.data.Undefined16",
			Undefined16DataType.class.getName());
	}

	private final static long serialVersionUID = 1;

	/** A statically defined DefaultDataType used when an Undefined byte is needed.*/
	public final static Undefined16DataType dataType = new Undefined16DataType();

	/**
	 * Construcs a new Undefined16 dataType
	 *
	 */
	public Undefined16DataType() {
		this(null);
	}

	public Undefined16DataType(DataTypeManager dtm) {
		super("undefined16", dtm);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	public int getLength() {
		return 16;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	public String getDescription() {
		return "Undefined 16-Byte";
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getMnemonic(Settings)
	 */
	public String getMnemonic(Settings settings) {
		return name;
	}

	private long getValue(MemBuffer buf) throws MemoryAccessException {
        // Only get the least significant 8 bytes, the higher bits can only be metadata in CHERI
		return buf.getLong(0);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getRepresentation(MemBuffer, Settings, int)
	 */
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		String val = "??";

		try {
			long b = getValue(buf);
			val = Long.toHexString(b).toUpperCase();
			val = StringFormat.padIt(val, 16, 'h', true);
		}
		catch (MemoryAccessException e) {
		}

		return val;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			return new Scalar(64, getValue(buf));
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Undefined16DataType(dtm);
	}
}
