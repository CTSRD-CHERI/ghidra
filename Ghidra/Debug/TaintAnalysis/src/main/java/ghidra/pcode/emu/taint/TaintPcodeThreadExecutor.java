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
package ghidra.pcode.emu.taint;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.DefaultPcodeThread;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.taint.model.TaintVec;
import ghidra.util.Msg;

/**
 * An instrumented executor for the Taint Analyzer
 * 
 * <p>
 * This part is responsible for executing all the actual p-code operations generated by each decoded
 * instruction. Each thread in the emulator gets a distinct executor. So far, we haven't actually
 * added any instrumentation, but the conditions of {@link PcodeOp#CBRANCH} operations will likely
 * be examined by the user, so we set up the skeleton here.
 */
public class TaintPcodeThreadExecutor extends PcodeThreadExecutor<Pair<byte[], TaintVec>> {

	/**
	 * Create the executor
	 * 
	 * @param thread the thread being created
	 */
	public TaintPcodeThreadExecutor(DefaultPcodeThread<Pair<byte[], TaintVec>> thread) {
		super(thread);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This is invoked on every {@link PcodeOp#CBRANCH}, allowing us a decent place to instrument
	 * the emulator and add some diagnostics. Refer to
	 * {@link PcodeExecutor#executeConditionalBranch(PcodeOp, PcodeFrame)} to see the operations
	 * inputs. Alternatively, we could override
	 * {@link TaintPcodeArithmetic#isTrue(TaintVec, Purpose)}; however, we'd have access to less
	 * contextual information at that position.
	 */
	@Override
	public void executeConditionalBranch(PcodeOp op, PcodeFrame frame) {
		Pair<byte[], TaintVec> condition = state.getVar(op.getInput(1), reason);
		TaintVec taint = condition.getRight();
		if (!taint.union().isEmpty()) {
			// getInstruction may return null if an inject executes a CBRANCH
			Msg.trace(this, "Conditional branch '" + thread.getInstruction() + "' at " +
				thread.getCounter() + " decided by tainted value: " + taint);
			// TODO: Record these somewhere more useful.
		}
		super.executeConditionalBranch(op, frame);
	}
}
