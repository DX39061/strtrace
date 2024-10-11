var ranges = Process.enumerateRanges("rw-");
function is_valid_pointer(reg_val: NativePointer) {
  let valid = false;
  ranges.forEach((range) => {
    let start = range.base;
    let end = range.base.add(range.size);
    if (reg_val.compare(start) >= 0 && reg_val.compare(end) <= 0) {
      valid = true;
    }
  });
  return valid;
}

const object_getClass = new NativeFunction(
  Module.findExportByName(null, "object_getClass")!,
  "pointer",
  ["pointer"]
);
const class_getName = new NativeFunction(
  Module.findExportByName(null, "class_getName")!,
  "pointer",
  ["pointer"]
);

var last_nsuserdefaults: string = "";

function extract_string(reg_val: NativePointer) {
  let str: string | null = null;
  // case 1: swift inline hex string
  let has_error = false;
  try {
    var last_byte_int = 1;
    str = reg_val
      .toString(16)
      .match(/.{1,2}/g)!
      .map((byte) => {
        let byte_int = parseInt(byte, 16);
        if (last_byte_int === 0) {
          return String.fromCharCode(0);
        }
        last_byte_int = byte_int;
        if (byte_int < 0x20 || byte_int > 0x7e) {
          throw new Error("Invalid char");
        }
        return String.fromCharCode(byte_int);
      })
      .join("");

    str = str.split("").reverse().join("");
  } catch (e) {
    has_error = true;
  }
  if (!has_error && str?.trim() !== "" && str?.trim().length! >= 3) {
    return str;
  }

  // case 2: pointer to objc object
  if (!is_valid_pointer(reg_val)) return null;
  has_error = false;
  try {
    // console.log("reg_val: " + reg_val);
    const classPtr = object_getClass(reg_val);
    if (!is_valid_pointer(classPtr)) {
      throw new Error("Invalid object");
    }
    const class_name = class_getName(classPtr).readUtf8String();
    if (classPtr === null || class_name === null || class_name === "nil") {
      throw new Error("Invalid object");
    }
    // console.log("class_name: " + class_name);
    switch (class_name) {
      case "Foundation.__NSSwiftData":
      case "NSConcreteData":
      case "NSConcreteMutableData":
        let nsdata = new ObjC.Object(reg_val);
        let bytes = nsdata.bytes();
        let length = nsdata.length();
        let data_str = "";
        for (let i = 0; i < length; i++) {
          let byte = bytes.add(i).readU8();
          data_str += String.fromCharCode(byte);
        }
        str = "[" + class_name + "] " + data_str;
        break;
      case "NSUserDefaults":
        let nsuserdefaults = new ObjC.Object(reg_val);
        let dict = nsuserdefaults.dictionaryRepresentation().toString();
        if (last_nsuserdefaults !== dict) {
          last_nsuserdefaults = dict;
          str = "[" + class_name + "] " + dict;
        } else {
          str = "[" + class_name + "] ";
        }
        break;
      case "NSObject":
      case "NSString":
      case "NSMutableString":
      case "NSConstantString":
      case "NSCFString":
      case "NSTaggedPointerString":
      case "NSArray":
      case "NSDictionary":
      case "NSSet":
      case "NSError":
      case "_NSClStr":
      case "__NSDictionaryM":
      case "__NSArrayI":
      case "__NSArrayM":
      case "__NSCFConstantString":
      case "__NSCFString":
      case "Swift.__SharedStringStorage":
      case "Swift.__StringStorage":
        let obj = new ObjC.Object(reg_val);
        if (obj === null || obj.$kind !== "instance") {
          throw new Error("Invalid object");
        }
        str = "[" + class_name + "] " + obj;
        break;
      default:
        str = "[" + class_name + "] ";
        break;
    }
  } catch (e) {
    has_error = true;
  }
  if (!has_error && str !== "") {
    return str;
  }

  return null;
}

var is_tracing = false;
function set_trace(module_name: string, function_offset: number) {
  let module: Module = Process.getModuleByName(module_name);
  let func_addr: NativePointer = module.base.add(function_offset);
  Interceptor.attach(func_addr, {
    onEnter: function () {
      console.error("start tracing...");
      console.log(
        "Entering " +
          module_name +
          "!" +
          func_addr +
          "---" +
          func_addr.sub(module.base) +
          "-----------------"
      );
      if (is_tracing) {
        return;
      }
      is_tracing = true;
      this.current_pid = Process.getCurrentThreadId();
      Stalker.follow(this.current_pid, {
        transform: (iterator: StalkerArm64Iterator) => {
          let instruction = iterator.next();
          do {
            iterator.keep();
            if (instruction === null) {
              // console.log("Instruction is null");
            } else if (
              instruction.address.compare(func_addr) < 0 ||
              instruction.address.compare(module.base.add(module.size)) > 0
            ) {
              // console.log("Instruction is out of moudule");
            } else {
              // print every instruction
              // let address = "0x" + ((instruction.address as unknown as number) - (module.base as unknown as number)).toString(16).padStart(8, '0');
              // let mnemonic = instruction.mnemonic;
              // let operands = instruction.opStr;
              // console.log(`${address.padEnd(12, ' ')}  ${mnemonic.padEnd(8, ' ') + operands}`);

              iterator.putCallout((context: CpuContext) => {
                let contextArm64: Arm64CpuContext = context as Arm64CpuContext;
                let check_regs = [
                  "x0",
                  "x1",
                  "x2",
                  "x3",
                  "x4",
                  "x5",
                  "x6",
                  "x7",
                  "x19",
                  "x20",
                  "x21",
                  "x22",
                  "x23",
                  "x24",
                  "x25",
                  "x26",
                  "x27",
                  "x28",
                ];
                let pc =
                  "0x" +
                  (
                    (contextArm64.pc as unknown as number) -
                    (module.base as unknown as number)
                  )
                    .toString(16)
                    .padStart(8, "0");
                var out = `${pc.toString().padEnd(12, " ")}`;
                check_regs.forEach((reg) => {
                  let value = contextArm64[reg as keyof Arm64CpuContext];
                  if (value instanceof ArrayBuffer) {
                    if (out.length > 12) out += "\t";
                    out += `  ${reg} = ${value}`;
                  } else if (value instanceof NativePointer) {
                    let str = extract_string(value);
                    if (str !== null) {
                      if (out.length > 12) out += "\t";
                      out += `  ${reg}: ${str}`;
                    }
                  } else {
                    if (out.length > 12) out += "\t";
                    out += `[number]${reg}: ${value}`;
                  }
                });
                if (out.length > 12) {
                  console.log(out);
                }
              });
            }
          } while (iterator.next() !== null);
        },
      });
    },
    onLeave: function () {
      console.log(
        "Leaving  " +
          module_name +
          "!" +
          func_addr +
          "---" +
          func_addr.sub(module.base) +
          "-----------------\n"
      );
      Stalker.unfollow(this.current_pid);
      Stalker.garbageCollect();
      send({
        type: "finish",
        data: "",
      });
    },
  });
}

function main() {
  recv("args", (data) => {
    try {
      let args = data.data;
      let module_name = args.module_name;
      let function_offset = args.function_offset;
      console.log("module_name: " + module_name);
      console.log(
        "function_offset: 0x" + parseInt(function_offset).toString(16)
      );
      set_trace(module_name, function_offset);
    } catch (e) {
      console.error(e);
    }
  });
}

main();
