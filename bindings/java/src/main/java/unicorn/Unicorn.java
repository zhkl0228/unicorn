/*

Java bindings for the Unicorn Emulator Engine

Copyright(c) 2015 Chris Eagle

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

package unicorn;

import java.io.IOException;
import java.util.*;

public class Unicorn implements UnicornConst, ArmConst, Arm64Const {

   private final long eng;
   private final int arch;
   private final int mode;

   private final List<UnHook> hookList = new ArrayList<>();

   private static final int[] EVENT_MEM_HOOK_TYPES = {
      UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED,
      UC_HOOK_MEM_READ_PROT, UC_HOOK_MEM_WRITE_PROT, UC_HOOK_MEM_FETCH_PROT,
      UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_FETCH, UC_HOOK_MEM_READ_AFTER
   };

   static {
      try {
         org.scijava.nativelib.NativeLoader.loadLibrary("unicorn_java");
      } catch (IOException e) {
         throw new IllegalStateException(e);
      }
   }

   public class UnHook {
      private final long handle;
      public UnHook(long handle) {
         this.handle = handle;
         hookList.add(this);
      }
      public void unhook() {
         unhookInternal();
         hookList.remove(this);
      }
      private boolean unhooked;
      private void unhookInternal() {
         if (!unhooked) {
            hook_del(handle);
         }
         unhooked = true;
      }
   }

   private class NewHook {
      public final Hook function;
      public final Object data;
      public NewHook(Hook f, Object d) {
         function = f;
         data = d;
      }

      void onBlock(long address, int size) {
         ((BlockHook) function).hook(Unicorn.this, address, size, data);
      }

      void onCode(long address, int size) {
         ((CodeHook) function).hook(Unicorn.this, address, size, data);
      }

      void onBreak(long address, int size) {
         ((DebugHook) function).onBreak(Unicorn.this, address, size, data);
      }

      void onRead(long address, int size) {
         ((ReadHook) function).hook(Unicorn.this, address, size, data);
      }

      void onWrite(long address, int size, long value) {
         ((WriteHook) function).hook(Unicorn.this, address, size, value, data);
      }

      void onInterrupt(int intno) {
         ((InterruptHook) function).hook(Unicorn.this, intno, data);
      }

      boolean onMemEvent(int type, long address, int size, long value) {
         return ((EventMemHook) function).hook(Unicorn.this, address, size, value, data);
      }
   }

   private native void reg_write_num(int regid, Number value) throws UnicornException;

   private native Number reg_read_num(int regid) throws UnicornException;

   private native long open(int arch, int mode) throws UnicornException;

/**
 * Create a new Unicorn object
 *
 * @param  arch  Architecture type (UC_ARCH_*)
 * @param  mode  Hardware mode. This is combined of UC_MODE_*
 * @see    unicorn.UnicornConst
 */
   public Unicorn(int arch, int mode) throws UnicornException {
      this.arch = arch;
      this.mode = mode;
      eng = open(arch, mode);
   }

/**
 * Return combined API version & major and minor version numbers.
 *
 * @return hexadecimal number as (major << 8 | minor), which encodes both major & minor versions.
 */
   public native static int version();

/**
 *  Determine if the given architecture is supported by this library.
 *
 *  @param   arch   Architecture type (UC_ARCH_*)
 *  @return  true if this library supports the given arch.
 *  @see     unicorn.UnicornConst
 */
   public native static boolean arch_supported(int arch);

/**
 * Return a string describing given error code.
 *
 * @param  code   Error code (see UC_ERR_* above)
 * @return Returns a String that describes the error code
 * @see unicorn.UnicornConst
 */
   public native static String strerror(int code);

/**
 * Free a resource allocated within Unicorn. Use for handles
 * allocated by context_alloc.
 *
 * @param handle Previously allocated Unicorn object handle.
 */
   public native static void free(long handle);

   public void closeAll() throws UnicornException {
      for (UnHook unHook : hookList) {
         unHook.unhookInternal();
      }
      close();
   }

   private native void close() throws UnicornException;

/**
 * Query internal status of engine.
 *
 * @param   type     query type. See UC_QUERY_*
 * @return  error code. see UC_ERR_*
 * @see     unicorn.UnicornConst
 */
   public native int query(int type) throws UnicornException;

/**
 * Report the last error number when some API function fail.
 * Like glibc's errno, uc_errno might not retain its old value once accessed.
 *
 * @return Error code of uc_err enum type (UC_ERR_*, see above)
 * @see unicorn.UnicornConst
 */
   public native int errno();

/**
 * Write to register.
 *
 * @deprecated use reg_write(int regid, long value) instead
 * @param  regid  Register ID that is to be modified.
 * @param  value  Array containing value that will be written into register @regid
 */
@Deprecated
   public native void reg_write(int regid, byte[] value) throws UnicornException;

/**
 * Write to register.
 *
 * @param  regid  Register ID that is to be modified.
 * @param  value  long value to be written into register
 */
   public void reg_write(int regid, long value) throws UnicornException {
      reg_write_num(regid, value);
   }

/**
 * Read register value.
 *
 * @deprecated use long reg_read(int regid) instead
 * @param regid  Register ID that is to be retrieved.
 * @param regsz  Size of the register being retrieved.
 * @return Byte array containing the requested register value.
 */
@Deprecated
   public native byte[] reg_read(int regid, int regsz) throws UnicornException;

/**
 * Read register value.
 *
 * @param regid  Register ID that is to be retrieved.
 * @return long value of the requested register.
 */
   public long reg_read(int regid) throws UnicornException {
      return reg_read_num(regid).longValue();
   }

/**
 * Batch write register values.
 *
 * @param regids  Array of register IDs to be written.
 * @param vals  Array of register values to be written.
 */
   public void reg_write_batch(int[] regids, long[] vals) throws UnicornException {
      if (regids.length != vals.length) {
         throw new UnicornException(strerror(UC_ERR_ARG));
      }
      for (int i = 0; i < regids.length; i++) {
         reg_write(regids[i], vals[i]);
      }
   }

/**
 * Batch read register values.
 *
 * @param regids  Array of register IDs to be read.
 * @return Array containing the requested register values.
 */
   public long[] reg_read_batch(int[] regids) throws UnicornException {
      long[] vals = new long[regids.length];
      for (int i = 0; i < regids.length; i++) {
         vals[i] = reg_read(regids[i]);
      }
      return vals;
   }

/**
 * Write to memory.
 *
 * @param  address  Start address of the memory region to be written.
 * @param  bytes    The values to be written into memory. bytes.length bytes will be written.
 */
   public native void mem_write(long address, byte[] bytes) throws UnicornException;

/**
 * Read memory contents.
 *
 * @param address  Start address of the memory region to be read.
 * @param size     Number of bytes to be retrieved.
 * @return Byte array containing the contents of the requested memory range.
 */
   public native byte[] mem_read(long address, long size) throws UnicornException;

/**
 * Emulate machine code in a specific duration of time.
 *
 * @param begin    Address where emulation starts
 * @param until    Address where emulation stops (i.e when this address is hit)
 * @param timeout  Duration to emulate the code (in microseconds). When this value is 0,
 *                 we will emulate the code in infinite time, until the code is finished.
 * @param count    The number of instructions to be emulated. When this value is 0,
 *                 we will emulate all the code available, until the code is finished.
 */
   public native void emu_start(long begin, long until, long timeout, long count) throws UnicornException;

/**
 * Stop emulation (which was started by emu_start()).
 * This is typically called from callback functions registered via tracing APIs.
 * NOTE: for now, this will stop the execution only after the current block.
 */
   public native void emu_stop() throws UnicornException;

   private native static long registerHook(long eng, int type, NewHook hook);

   private native static long registerHook(long eng, int type, long begin, long end, NewHook hook);

   private native static long registerDebugger(long eng, long begin, long end, NewHook hook);

   public native void setFastDebug(boolean fastDebug);
   public native void setSingleStep(int singleStep);
   public native void addBreakPoint(long address);
   public native void removeBreakPoint(long address);

   private native void hook_del(long handle) throws UnicornException;

/**
 * Hook registration for UC_HOOK_BLOCK hooks.
 *
 * @param callback  Implementation of a BlockHook interface
 * @param begin     Start address of hooking range
 * @param end       End address of hooking range
 * @param user_data User data to be passed to the callback function each time the event is triggered
 * @return UnHook handle that can be used to remove the hook
 */
   public UnHook hook_add(BlockHook callback, long begin, long end, Object user_data) throws UnicornException {
      NewHook hook = new NewHook(callback, user_data);
      long handle = registerHook(eng, UC_HOOK_BLOCK, begin, end, hook);
      return new UnHook(handle);
   }

/**
 * Hook registration for UC_HOOK_INTR hooks.
 *
 * @param callback  Implementation of an InterruptHook interface
 * @param user_data User data to be passed to the callback function each time the event is triggered
 * @return UnHook handle that can be used to remove the hook
 */
   public UnHook hook_add(InterruptHook callback, Object user_data) throws UnicornException {
      NewHook hook = new NewHook(callback, user_data);
      long handle = registerHook(eng, UC_HOOK_INTR, hook);
      return new UnHook(handle);
   }

/**
 * Hook registration for UC_HOOK_CODE hooks.
 *
 * @param callback  Implementation of a CodeHook interface
 * @param begin     Start address of hooking range
 * @param end       End address of hooking range
 * @param user_data User data to be passed to the callback function each time the event is triggered
 * @return UnHook handle that can be used to remove the hook
 */
   public UnHook hook_add(CodeHook callback, long begin, long end, Object user_data) throws UnicornException {
      NewHook hook = new NewHook(callback, user_data);
      long handle = registerHook(eng, UC_HOOK_CODE, begin, end, hook);
      return new UnHook(handle);
   }

   public UnHook debugger_add(DebugHook callback, long begin, long end, Object user_data) throws UnicornException {
      NewHook hook = new NewHook(callback, user_data);
      long handle = registerDebugger(eng, begin, end, hook);
      return new UnHook(handle);
   }

/**
 * Hook registration for UC_HOOK_MEM_READ hooks.
 *
 * @param callback  Implementation of a ReadHook interface
 * @param begin     Start address of memory read range
 * @param end       End address of memory read range
 * @param user_data User data to be passed to the callback function each time the event is triggered
 * @return UnHook handle that can be used to remove the hook
 */
   public UnHook hook_add(ReadHook callback, long begin, long end, Object user_data) throws UnicornException {
      NewHook hook = new NewHook(callback, user_data);
      long handle = registerHook(eng, UC_HOOK_MEM_READ, begin, end, hook);
      return new UnHook(handle);
   }

/**
 * Hook registration for UC_HOOK_MEM_WRITE hooks.
 *
 * @param callback  Implementation of a WriteHook interface
 * @param begin     Start address of memory write range
 * @param end       End address of memory write range
 * @param user_data User data to be passed to the callback function each time the event is triggered
 * @return UnHook handle that can be used to remove the hook
 */
   public UnHook hook_add(WriteHook callback, long begin, long end, Object user_data) throws UnicornException {
      NewHook hook = new NewHook(callback, user_data);
      long handle = registerHook(eng, UC_HOOK_MEM_WRITE, begin, end, hook);
      return new UnHook(handle);
   }

/**
 * Hook registration for UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE hooks.
 *
 * @param callback  Implementation of a MemHook interface
 * @param begin     Start address of memory range
 * @param end       End address of memory range
 * @param user_data User data to be passed to the callback function each time the event is triggered
 * @return Array of UnHook handles (read hook, write hook)
 */
   public UnHook[] hook_add(MemHook callback, long begin, long end, Object user_data) throws UnicornException {
      return new UnHook[] {
         hook_add((ReadHook) callback, begin, end, user_data),
         hook_add((WriteHook) callback, begin, end, user_data)
      };
   }

/**
 * Hook registration for UC_HOOK_MEM_XXX_UNMAPPED and UC_HOOK_MEM_XXX_PROT hooks.
 *
 * @param callback  Implementation of an EventMemHook interface
 * @param type      Type of memory event being hooked such as UC_HOOK_MEM_READ_UNMAPPED
 * @param user_data User data to be passed to the callback function each time the event is triggered
 * @return Map of hook type to UnHook handle
 */
   public Map<Integer, UnHook> hook_add(EventMemHook callback, int type, Object user_data) throws UnicornException {
      Map<Integer, UnHook> map = new HashMap<>();
      for (int htype : EVENT_MEM_HOOK_TYPES) {
         if ((type & htype) != 0) {
            NewHook hook = new NewHook(callback, user_data);
            long handle = registerHook(eng, htype, hook);
            map.put(htype, new UnHook(handle));
         }
      }
      return map;
   }

/**
 * Map a range of memory.
 *
 * @param address Base address of the memory range
 * @param size    Size of the memory block.
 * @param perms   Permissions on the memory block. A combination of UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
 */
   public native void mem_map(long address, long size, int perms) throws UnicornException;

/**
 *  Map existing host memory in for emulation.
 *
 * @param address Base address of the memory range
 * @param size    Size of the memory block.
 * @param perms   Permissions on the memory block. A combination of UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
 * @param block   Block of host memory backing the newly mapped memory.
 */
   public native void mem_map_ptr(long address, long size, int perms, byte[] block) throws UnicornException;

/**
 * Unmap a range of memory.
 *
 * @param address Base address of the memory range
 * @param size    Size of the memory block.
 */
   public native void mem_unmap(long address, long size) throws UnicornException;

/**
 * Change permissions on a range of memory.
 *
 * @param address Base address of the memory range
 * @param size    Size of the memory block.
 * @param perms   New permissions on the memory block. A combination of UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
 */
   public native void mem_protect(long address, long size, int perms) throws UnicornException;

/**
 * Retrieve all memory regions mapped by mem_map() and mem_map_ptr().
 * NOTE: memory regions may be split by mem_unmap()
 *
 * @return  list of mapped regions.
 */
   public native MemRegion[] mem_regions() throws UnicornException;

/**
 * Allocate a region that can be used with uc_context_{save,restore} to perform
 * quick save/rollback of the CPU context, which includes registers and some
 * internal metadata.
 *
 * @return context handle for use with save/restore.
 */
   public native long context_alloc();

/**
 * Save a copy of the internal CPU context.
 *
 * @param context handle previously returned by context_alloc.
 */
   public native void context_save(long context);

/**
 * Restore the current CPU context from a saved copy.
 *
 * @param context handle previously returned by context_alloc.
 */
   public native void context_restore(long context);

}
