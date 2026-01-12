# api/datatype.py
"""DataType API - 数据类型设置、创建、管理和解析"""

import re
import json
import tempfile
import os

from api import route
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    CategoryPath,
    DataTypePath,
    DataTypeConflictHandler,
    StructureDataType,
    EnumDataType,
    TypedefDataType,
    UnionDataType,
    FunctionDefinitionDataType,
    ParameterDefinitionImpl,
    ArrayDataType,
    PointerDataType,
    # Built-in types
    IntegerDataType,
    UnsignedIntegerDataType,
    CharDataType,
    UnsignedCharDataType,
    ShortDataType,
    UnsignedShortDataType,
    LongDataType,
    UnsignedLongDataType,
    LongLongDataType,
    UnsignedLongLongDataType,
    FloatDataType,
    DoubleDataType,
    VoidDataType,
    BooleanDataType,
    ByteDataType,
    WordDataType,
    DWordDataType,
    QWordDataType,
    SignedByteDataType,
    SignedWordDataType,
    SignedDWordDataType,
    SignedQWordDataType,
    Undefined1DataType,
    Undefined2DataType,
    Undefined4DataType,
    Undefined8DataType,
)
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.data import BuiltInDataTypeManager, DataTypeWriter
from java.io import StringWriter


# ============================================================
# 辅助函数
# ============================================================

def _get_all_dtms(state):
    """
    获取所有可用的 DataTypeManager。

    Returns:
        list of (name, dtm) tuples
    """
    dtms = []

    # 1. BuiltIn types
    try:
        builtin_dtm = BuiltInDataTypeManager.getDataTypeManager()
        if builtin_dtm:
            dtms.append(("BuiltInTypes", builtin_dtm))
    except Exception:
        pass

    # 2. Program's own DTM
    prog = state.getCurrentProgram()
    if prog:
        prog_dtm = prog.getDataTypeManager()
        prog_name = prog.getName() if prog else "Program"
        dtms.append((prog_name, prog_dtm))

    # 3. Try to get DataTypeManagerService for open archives (GUI mode)
    try:
        tool = state.getTool()
        if tool:
            from ghidra.app.services import DataTypeManagerService
            dtm_service = tool.getService(DataTypeManagerService)
            if dtm_service:
                # Get all open DataTypeManagers
                for dtm in dtm_service.getDataTypeManagers():
                    name = dtm.getName()
                    # Avoid duplicates
                    if not any(n == name for n, _ in dtms):
                        dtms.append((name, dtm))
    except Exception:
        pass

    return dtms


def _get_dtm_by_name(state, archive_name):
    """
    根据名称获取指定的 DataTypeManager。

    Args:
        state: Ghidra state
        archive_name: 归档名称，空字符串或 None 表示当前程序

    Returns:
        (dtm, error) 二元组
    """
    if not archive_name:
        # Default to program's DTM
        prog = state.getCurrentProgram()
        if not prog:
            return None, _make_error("No program loaded")
        return prog.getDataTypeManager(), None

    # Search in all DTMs
    for name, dtm in _get_all_dtms(state):
        if name == archive_name or name.lower() == archive_name.lower():
            return dtm, None

    # List available archives for error message
    available = [n for n, _ in _get_all_dtms(state)]
    return None, _make_error(f"Archive not found: {archive_name}. Available: {available}")

def _make_success(data):
    """构造成功响应"""
    return {"success": True, **data}


def _make_error(message):
    """构造错误响应"""
    return {"success": False, "error": message}


def _get_program(state):
    """获取当前程序"""
    prog = state.getCurrentProgram()
    if not prog:
        return None, _make_error("No program loaded")
    return prog, None


def _parse_address(prog, addr_str):
    """解析地址字符串"""
    try:
        addr = prog.getAddressFactory().getAddress(addr_str)
        if addr is None:
            return None, _make_error(f"Invalid address: {addr_str}")
        return addr, None
    except Exception as e:
        return None, _make_error(f"Address parse error: {str(e)}")


def _find_function(state, address="", name=""):
    """
    查找函数。

    Returns:
        (prog, func, error) 三元组
    """
    prog, err = _get_program(state)
    if err:
        return None, None, err

    fm = prog.getFunctionManager()
    func = None

    if address:
        addr, err = _parse_address(prog, address)
        if err:
            return None, None, err
        func = fm.getFunctionAt(addr)
        if func is None:
            func = fm.getFunctionContaining(addr)
    elif name:
        for f in fm.getFunctions(True):
            if f.getName() == name:
                func = f
                break
    else:
        return None, None, _make_error("Must provide 'address' or 'name'")

    if func is None:
        return None, None, _make_error(f"Function not found: {address or name}")

    return prog, func, None


def _decompile_function(prog, func, timeout=30):
    """
    反编译函数并返回 HighFunction。

    Returns:
        (high_func, error) 二元组
    """
    decomp = DecompInterface()
    decomp.openProgram(prog)

    try:
        monitor = ConsoleTaskMonitor()
        results = decomp.decompileFunction(func, int(timeout), monitor)

        if not results.decompileCompleted():
            error_msg = results.getErrorMessage()
            return None, _make_error(f"Decompilation failed: {error_msg}")

        high_func = results.getHighFunction()
        if high_func is None:
            return None, _make_error("Decompilation returned no HighFunction")

        return high_func, None
    finally:
        decomp.dispose()


# Built-in type mapping
_BUILTIN_TYPES = {
    # Signed integers
    "int": IntegerDataType.dataType,
    "int32": IntegerDataType.dataType,
    "int32_t": IntegerDataType.dataType,
    "char": CharDataType.dataType,
    "short": ShortDataType.dataType,
    "int16": ShortDataType.dataType,
    "int16_t": ShortDataType.dataType,
    "long": LongDataType.dataType,
    "longlong": LongLongDataType.dataType,
    "long long": LongLongDataType.dataType,
    "int64": LongLongDataType.dataType,
    "int64_t": LongLongDataType.dataType,
    "int8": SignedByteDataType.dataType,
    "int8_t": SignedByteDataType.dataType,

    # Unsigned integers
    "uint": UnsignedIntegerDataType.dataType,
    "uint32": UnsignedIntegerDataType.dataType,
    "uint32_t": UnsignedIntegerDataType.dataType,
    "unsigned int": UnsignedIntegerDataType.dataType,
    "unsigned": UnsignedIntegerDataType.dataType,
    "uchar": UnsignedCharDataType.dataType,
    "unsigned char": UnsignedCharDataType.dataType,
    "ushort": UnsignedShortDataType.dataType,
    "unsigned short": UnsignedShortDataType.dataType,
    "uint16": UnsignedShortDataType.dataType,
    "uint16_t": UnsignedShortDataType.dataType,
    "ulong": UnsignedLongDataType.dataType,
    "unsigned long": UnsignedLongDataType.dataType,
    "ulonglong": UnsignedLongLongDataType.dataType,
    "unsigned long long": UnsignedLongLongDataType.dataType,
    "uint64": UnsignedLongLongDataType.dataType,
    "uint64_t": UnsignedLongLongDataType.dataType,
    "uint8": ByteDataType.dataType,
    "uint8_t": ByteDataType.dataType,

    # Floating point
    "float": FloatDataType.dataType,
    "double": DoubleDataType.dataType,

    # Other
    "void": VoidDataType.dataType,
    "bool": BooleanDataType.dataType,
    "boolean": BooleanDataType.dataType,
    "_Bool": BooleanDataType.dataType,

    # Ghidra specific
    "byte": ByteDataType.dataType,
    "word": WordDataType.dataType,
    "dword": DWordDataType.dataType,
    "qword": QWordDataType.dataType,
    "sbyte": SignedByteDataType.dataType,
    "sword": SignedWordDataType.dataType,
    "sdword": SignedDWordDataType.dataType,
    "sqword": SignedQWordDataType.dataType,
    "undefined": Undefined1DataType.dataType,
    "undefined1": Undefined1DataType.dataType,
    "undefined2": Undefined2DataType.dataType,
    "undefined4": Undefined4DataType.dataType,
    "undefined8": Undefined8DataType.dataType,

    # Size-specific (platform dependent in reality, but commonly)
    "size_t": UnsignedLongLongDataType.dataType,
    "ssize_t": LongLongDataType.dataType,
    "ptrdiff_t": LongLongDataType.dataType,
    "intptr_t": LongLongDataType.dataType,
    "uintptr_t": UnsignedLongLongDataType.dataType,
}


def _resolve_datatype(dtm, type_str):
    """
    解析类型字符串为 DataType 对象。

    支持:
    - 内置类型: int, char, void, float, double, etc.
    - 指针: int *, char **, void *
    - 数组: int[10], char[256]
    - 路径: /MyCategory/MyStruct
    - 简单名称: MyStruct

    Returns:
        DataType object

    Raises:
        ValueError if type not found
    """
    if type_str is None:
        raise ValueError("type_str cannot be None")

    type_str = type_str.strip()
    if not type_str:
        raise ValueError("type_str cannot be empty")

    # Handle pointers (rightmost * first)
    if type_str.endswith('*'):
        # Find base type by stripping trailing *
        base_str = type_str[:-1].strip()
        base_dt = _resolve_datatype(dtm, base_str)
        return dtm.getPointer(base_dt)

    # Handle arrays (e.g., "int[10]", "char[256]")
    array_match = re.match(r'^(.+)\[(\d+)\]$', type_str)
    if array_match:
        base_str = array_match.group(1).strip()
        count = int(array_match.group(2))
        base_dt = _resolve_datatype(dtm, base_str)
        return ArrayDataType(base_dt, count, base_dt.getLength())

    # Try built-in types first (case insensitive)
    type_lower = type_str.lower()
    if type_lower in _BUILTIN_TYPES:
        return _BUILTIN_TYPES[type_lower]

    # Try as category path (starts with /)
    if type_str.startswith('/'):
        try:
            dt_path = DataTypePath(type_str)
            dt = dtm.getDataType(dt_path)
            if dt:
                return dt
        except Exception:
            pass
        # Try direct path lookup
        dt = dtm.getDataType(type_str)
        if dt:
            return dt

    # Search by exact name
    for dt in dtm.getAllDataTypes():
        if dt.getName() == type_str:
            return dt

    # Search by name ignoring case
    for dt in dtm.getAllDataTypes():
        if dt.getName().lower() == type_lower:
            return dt

    raise ValueError(f"Data type not found: {type_str}")


def _resolve_datatype_safe(dtm, type_str):
    """
    安全版本的 _resolve_datatype，返回 (datatype, error) 二元组。
    """
    try:
        dt = _resolve_datatype(dtm, type_str)
        return dt, None
    except ValueError as e:
        return None, _make_error(str(e))
    except Exception as e:
        return None, _make_error(f"Failed to resolve type '{type_str}': {str(e)}")


def _resolve_field_ordinal(struct_dt, field):
    """
    根据字段名称或索引获取 ordinal。

    Args:
        struct_dt: Structure DataType
        field: 字段名称或索引（字符串或整数）

    Returns:
        (ordinal, error) 二元组
    """
    # Try as index
    try:
        ordinal = int(field)
        num_components = struct_dt.getNumComponents()
        if 0 <= ordinal < num_components:
            return ordinal, None
        return None, _make_error(f"Field index {ordinal} out of range (0-{num_components - 1})")
    except (ValueError, TypeError):
        pass

    # Try as name
    for i in range(struct_dt.getNumComponents()):
        comp = struct_dt.getComponent(i)
        if comp.getFieldName() == field:
            return i, None

    # List available fields for error message
    field_names = []
    for i in range(struct_dt.getNumComponents()):
        comp = struct_dt.getComponent(i)
        name = comp.getFieldName()
        if name:
            field_names.append(name)

    return None, _make_error(f"Field not found: {field}. Available: {field_names}")


# ============================================================
# Part A: 类型设置 API
# ============================================================

@route("/api/datatype/set/return")
def set_return_type(state, function="", function_address="", type=""):
    """
    设置函数返回类型。

    路由: GET /api/datatype/set/return?function=main&type=int
          GET /api/datatype/set/return?function_address=0x401000&type=void *

    参数:
        function: 函数名 (与 function_address 二选一)
        function_address: 函数地址 (与 function 二选一)
        type: 数据类型（支持内置类型、指针、数组、路径）
    """
    if not type:
        return _make_error("type is required")

    prog, func, err = _find_function(state, function_address, function)
    if err:
        return err

    dtm = prog.getDataTypeManager()
    new_dt, err = _resolve_datatype_safe(dtm, type)
    if err:
        return err

    old_return_type = str(func.getReturnType())

    tx_id = prog.startTransaction("Set Return Type")
    try:
        func.setReturnType(new_dt, SourceType.USER_DEFINED)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to set return type: {str(e)}")

    return _make_success({
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "old_return_type": old_return_type,
        "new_return_type": str(func.getReturnType()),
        "type": "return_type"
    })


@route("/api/datatype/set/parameter")
def set_parameter_type(state, function="", function_address="", param="", type=""):
    """
    设置函数参数类型。

    路由: GET /api/datatype/set/parameter?function=main&param=0&type=int
          GET /api/datatype/set/parameter?function=main&param=argc&type=int

    参数:
        function: 函数名 (与 function_address 二选一)
        function_address: 函数地址 (与 function 二选一)
        param: 参数索引(0,1,2...)或参数名
        type: 数据类型
    """
    if not param and param != 0:
        return _make_error("param is required (index or name)")
    if not type:
        return _make_error("type is required")

    prog, func, err = _find_function(state, function_address, function)
    if err:
        return err

    dtm = prog.getDataTypeManager()
    new_dt, err = _resolve_datatype_safe(dtm, type)
    if err:
        return err

    params = func.getParameters()
    target_param = None

    # Try as index
    try:
        param_index = int(param)
        if 0 <= param_index < len(params):
            target_param = params[param_index]
    except (ValueError, TypeError):
        # Try as name
        for p in params:
            if p.getName() == str(param):
                target_param = p
                break

    if target_param is None:
        available = [p.getName() for p in params]
        return _make_error(f"Parameter not found: {param}. Available: {available}")

    old_type = str(target_param.getDataType())
    param_name = target_param.getName()
    ordinal = target_param.getOrdinal()

    tx_id = prog.startTransaction("Set Parameter Type")
    try:
        target_param.setDataType(new_dt, SourceType.USER_DEFINED)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to set parameter type: {str(e)}")

    return _make_success({
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "parameter": param_name,
        "ordinal": ordinal,
        "old_type": old_type,
        "new_type": str(target_param.getDataType()),
        "type": "parameter_type"
    })


@route("/api/datatype/set/decompiler/variable")
def set_decompiler_variable_type(state, function="", function_address="", var_name="", type="", timeout=30):
    """
    设置反编译器中局部变量的类型（推荐方式）。

    路由: GET /api/datatype/set/decompiler/variable?function=main&var_name=local_8&type=int
          GET /api/datatype/set/decompiler/variable?function_address=0x401000&var_name=uVar1&type=char *

    参数:
        function: 函数名 (与 function_address 二选一)
        function_address: 函数地址 (与 function 二选一)
        var_name: 变量名（反编译视图中显示的名称）
        type: 数据类型
        timeout: 反编译超时秒数 (默认 30)
    """
    if not var_name:
        return _make_error("var_name is required")
    if not type:
        return _make_error("type is required")

    prog, func, err = _find_function(state, function_address, function)
    if err:
        return err

    dtm = prog.getDataTypeManager()
    new_dt, err = _resolve_datatype_safe(dtm, type)
    if err:
        return err

    # Decompile function
    high_func, err = _decompile_function(prog, func, timeout)
    if err:
        return err

    # Find variable in LocalSymbolMap
    lsm = high_func.getLocalSymbolMap()
    target_sym = None

    for sym in lsm.getSymbols():
        if sym.getName() == var_name:
            target_sym = sym
            break

    if target_sym is None:
        available = [s.getName() for s in lsm.getSymbols()]
        return _make_error(f"Variable not found in decompiler: {var_name}. Available: {available[:20]}")

    old_type = "unknown"
    high_var = target_sym.getHighVariable()
    if high_var:
        old_type = str(high_var.getDataType())

    tx_id = prog.startTransaction("Set Decompiler Variable Type")
    try:
        # updateDBVariable(HighSymbol, String name, DataType dataType, SourceType source)
        # Pass None for name to keep existing name
        HighFunctionDBUtil.updateDBVariable(
            target_sym,
            None,  # Keep original name
            new_dt,
            SourceType.USER_DEFINED
        )
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to set variable type: {str(e)}")

    return _make_success({
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "variable": var_name,
        "old_type": old_type,
        "new_type": type,
        "type": "decompiler_variable_type"
    })


@route("/api/datatype/set/decompiler/parameter")
def set_decompiler_parameter_type(state, function="", function_address="", param="", type="", timeout=30):
    """
    设置反编译器中参数的类型（推荐方式）。

    路由: GET /api/datatype/set/decompiler/parameter?function=main&param=0&type=int
          GET /api/datatype/set/decompiler/parameter?function=main&param=param_1&type=char **

    参数:
        function: 函数名 (与 function_address 二选一)
        function_address: 函数地址 (与 function 二选一)
        param: 参数索引(0,1,2...)或参数名
        type: 数据类型
        timeout: 反编译超时秒数 (默认 30)
    """
    if not param and param != 0:
        return _make_error("param is required (index or name)")
    if not type:
        return _make_error("type is required")

    prog, func, err = _find_function(state, function_address, function)
    if err:
        return err

    dtm = prog.getDataTypeManager()
    new_dt, err = _resolve_datatype_safe(dtm, type)
    if err:
        return err

    # Decompile function
    high_func, err = _decompile_function(prog, func, timeout)
    if err:
        return err

    # Find parameter
    lsm = high_func.getLocalSymbolMap()
    target_sym = None
    param_index = None

    # Try as index
    try:
        param_index = int(param)
        count = 0
        for sym in lsm.getSymbols():
            if sym.isParameter():
                if count == param_index:
                    target_sym = sym
                    break
                count += 1
    except (ValueError, TypeError):
        # Try as name
        for sym in lsm.getSymbols():
            if sym.isParameter() and sym.getName() == str(param):
                target_sym = sym
                break

    if target_sym is None:
        available = [s.getName() for s in lsm.getSymbols() if s.isParameter()]
        return _make_error(f"Parameter not found: {param}. Available: {available}")

    param_name = target_sym.getName()
    old_type = "unknown"
    high_var = target_sym.getHighVariable()
    if high_var:
        old_type = str(high_var.getDataType())

    tx_id = prog.startTransaction("Set Decompiler Parameter Type")
    try:
        HighFunctionDBUtil.updateDBVariable(
            target_sym,
            None,  # Keep original name
            new_dt,
            SourceType.USER_DEFINED
        )
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to set parameter type: {str(e)}")

    return _make_success({
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "parameter": param_name,
        "old_type": old_type,
        "new_type": type,
        "type": "decompiler_parameter_type"
    })


@route("/api/datatype/set/global")
def set_global_type(state, address="", name="", type=""):
    """
    设置全局变量的类型。

    路由: GET /api/datatype/set/global?address=0x404000&type=int
          GET /api/datatype/set/global?name=g_config&type=ConfigStruct

    参数:
        address: 全局变量地址 (与 name 二选一)
        name: 全局变量名称 (与 address 二选一)
        type: 数据类型
    """
    if not type:
        return _make_error("type is required")
    if not address and not name:
        return _make_error("Must provide 'address' or 'name'")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()
    new_dt, err = _resolve_datatype_safe(dtm, type)
    if err:
        return err

    listing = prog.getListing()
    target_addr = None

    if address:
        target_addr, err = _parse_address(prog, address)
        if err:
            return err
    elif name:
        # Find by symbol name
        st = prog.getSymbolTable()
        from ghidra.program.model.symbol import SymbolType
        for sym in st.getAllSymbols(True):
            if sym.getName() == name:
                sym_type = sym.getSymbolType()
                if sym_type == SymbolType.GLOBAL_VAR or sym_type == SymbolType.GLOBAL or sym_type == SymbolType.LABEL:
                    target_addr = sym.getAddress()
                    break
        if target_addr is None:
            return _make_error(f"Global symbol not found: {name}")

    # Get old type info
    old_data = listing.getDataAt(target_addr)
    old_type = str(old_data.getDataType()) if old_data else "undefined"

    tx_id = prog.startTransaction("Set Global Type")
    try:
        # Clear existing data first
        if old_data:
            listing.clearCodeUnits(target_addr, target_addr.add(old_data.getLength() - 1), False)

        # Create new data with the specified type
        listing.createData(target_addr, new_dt)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to set global type: {str(e)}")

    return _make_success({
        "address": str(target_addr),
        "old_type": old_type,
        "new_type": type,
        "type": "global_type"
    })


@route("/api/datatype/set/field")
def set_struct_field_type(state, struct="", field="", type=""):
    """
    设置结构体字段的类型。

    路由: GET /api/datatype/set/field?struct=MyStruct&field=0&type=int
          GET /api/datatype/set/field?struct=/MyCategory/MyStruct&field=data&type=char *

    参数:
        struct: 结构体名称或路径
        field: 字段名称或索引(0,1,2...)
        type: 数据类型
    """
    if not struct:
        return _make_error("struct is required")
    if not field and field != 0:
        return _make_error("field is required (index or name)")
    if not type:
        return _make_error("type is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()

    # Resolve struct
    struct_dt, err = _resolve_datatype_safe(dtm, struct)
    if err:
        return err

    # Verify it's a structure
    from ghidra.program.model.data import Structure
    if not isinstance(struct_dt, Structure):
        return _make_error(f"'{struct}' is not a structure type")

    # Resolve new field type
    new_dt, err = _resolve_datatype_safe(dtm, type)
    if err:
        return err

    # Find field
    ordinal, err = _resolve_field_ordinal(struct_dt, field)
    if err:
        return err

    component = struct_dt.getComponent(ordinal)
    old_type = str(component.getDataType())
    field_name = component.getFieldName() or f"field_{ordinal}"
    comment = component.getComment() or ""

    tx_id = prog.startTransaction("Set Struct Field Type")
    try:
        # Replace the component with new type
        # replace(int ordinal, DataType dataType, int length, String fieldName, String comment)
        struct_dt.replace(ordinal, new_dt, new_dt.getLength(), field_name, comment)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to set field type: {str(e)}")

    return _make_success({
        "struct": struct,
        "struct_path": struct_dt.getPathName(),
        "field": field_name,
        "ordinal": ordinal,
        "old_type": old_type,
        "new_type": type,
        "type": "struct_field_type"
    })


# ============================================================
# Part B: 类型创建 API
# ============================================================

@route("/api/datatype/create/struct")
def create_struct(state, name="", category="/", packing=0, fields=""):
    """
    创建结构体。

    路由: GET /api/datatype/create/struct?name=Point&fields=[{"name":"x","type":"int"},{"name":"y","type":"int"}]
          GET /api/datatype/create/struct?name=Config&category=/MyTypes&packing=4&fields=[...]

    参数:
        name: 结构体名称
        category: 类别路径 (默认 /)
        packing: 对齐值 (0=默认, 1/2/4/8=显式对齐)
        fields: JSON 数组，每个元素 {"name": "...", "type": "...", "comment": "..."}
    """
    if not name:
        return _make_error("name is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()
    cat_path = CategoryPath(category)

    # Parse fields
    field_list = []
    if fields:
        try:
            field_list = json.loads(fields)
        except json.JSONDecodeError as e:
            return _make_error(f"Invalid fields JSON: {str(e)}")

    # Create structure
    struct = StructureDataType(cat_path, name, 0)

    # Set packing if specified
    packing = int(packing)
    if packing > 0:
        struct.setPackingEnabled(True)
        struct.setExplicitPackingValue(packing)

    # Add fields
    for i, field in enumerate(field_list):
        field_type_str = field.get("type", "")
        if not field_type_str:
            return _make_error(f"Field {i} missing 'type'")

        field_dt, err = _resolve_datatype_safe(dtm, field_type_str)
        if err:
            return _make_error(f"Field {i}: {err.get('error', 'unknown error')}")

        field_name = field.get("name", "")
        field_comment = field.get("comment", "")
        struct.add(field_dt, field_name, field_comment)

    # Add to DTM
    tx_id = prog.startTransaction("Create Struct")
    try:
        result = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to create struct: {str(e)}")

    # Build response with field info
    field_info = []
    for i in range(result.getNumComponents()):
        comp = result.getComponent(i)
        field_info.append({
            "name": comp.getFieldName() or f"field_{i}",
            "type": str(comp.getDataType()),
            "offset": comp.getOffset(),
            "size": comp.getLength()
        })

    return _make_success({
        "name": result.getName(),
        "path": result.getPathName(),
        "category": str(result.getCategoryPath()),
        "size": result.getLength(),
        "field_count": result.getNumComponents(),
        "fields": field_info,
        "type": "create_struct"
    })


@route("/api/datatype/create/enum")
def create_enum(state, name="", category="/", size=4, members=""):
    """
    创建枚举类型。

    路由: GET /api/datatype/create/enum?name=Status&members={"OK":0,"ERROR":1}
          GET /api/datatype/create/enum?name=Status&members=[{"name":"OK","value":0}]
          GET /api/datatype/create/enum?name=Color&size=1&category=/Enums&members=...

    参数:
        name: 枚举名称
        category: 类别路径 (默认 /)
        size: 枚举大小（字节），1/2/4/8 (默认 4)
        members: JSON 对象 {"name": value, ...} 或数组 [{"name": "...", "value": ...}]
    """
    if not name:
        return _make_error("name is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()
    cat_path = CategoryPath(category)

    # Parse members
    member_data = {}
    if members:
        try:
            parsed = json.loads(members)
            if isinstance(parsed, list):
                # Array format: [{"name": "OK", "value": 0}, ...]
                for m in parsed:
                    member_data[m["name"]] = m["value"]
            elif isinstance(parsed, dict):
                # Object format: {"OK": 0, "ERROR": 1}
                member_data = parsed
            else:
                return _make_error("members must be JSON object or array")
        except json.JSONDecodeError as e:
            return _make_error(f"Invalid members JSON: {str(e)}")
        except KeyError as e:
            return _make_error(f"Member missing required field: {str(e)}")

    # Create enum
    size = int(size)
    if size not in [1, 2, 4, 8]:
        return _make_error("size must be 1, 2, 4, or 8")

    enum = EnumDataType(cat_path, name, size)

    # Add members
    for member_name, member_value in member_data.items():
        enum.add(member_name, int(member_value))

    # Add to DTM
    tx_id = prog.startTransaction("Create Enum")
    try:
        result = dtm.addDataType(enum, DataTypeConflictHandler.REPLACE_HANDLER)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to create enum: {str(e)}")

    # Build member list for response
    member_list = []
    for member_name in result.getNames():
        member_list.append({
            "name": member_name,
            "value": result.getValue(member_name)
        })

    return _make_success({
        "name": result.getName(),
        "path": result.getPathName(),
        "category": str(result.getCategoryPath()),
        "size": result.getLength(),
        "member_count": len(member_list),
        "members": member_list,
        "type": "create_enum"
    })


@route("/api/datatype/create/typedef")
def create_typedef(state, name="", base_type="", category="/"):
    """
    创建 typedef。

    路由: GET /api/datatype/create/typedef?name=DWORD&base_type=uint
          GET /api/datatype/create/typedef?name=PCHAR&base_type=char *&category=/Windows

    参数:
        name: typedef 名称
        base_type: 基础类型
        category: 类别路径 (默认 /)
    """
    if not name:
        return _make_error("name is required")
    if not base_type:
        return _make_error("base_type is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()
    cat_path = CategoryPath(category)

    # Resolve base type
    base_dt, err = _resolve_datatype_safe(dtm, base_type)
    if err:
        return err

    # Create typedef
    typedef = TypedefDataType(cat_path, name, base_dt)

    # Add to DTM
    tx_id = prog.startTransaction("Create Typedef")
    try:
        result = dtm.addDataType(typedef, DataTypeConflictHandler.REPLACE_HANDLER)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to create typedef: {str(e)}")

    return _make_success({
        "name": result.getName(),
        "path": result.getPathName(),
        "category": str(result.getCategoryPath()),
        "base_type": str(result.getDataType()),
        "size": result.getLength(),
        "type": "create_typedef"
    })


@route("/api/datatype/create/union")
def create_union(state, name="", category="/", members=""):
    """
    创建联合体 (union)。

    路由: GET /api/datatype/create/union?name=Value&members=[{"name":"i","type":"int"},{"name":"f","type":"float"}]

    参数:
        name: 联合体名称
        category: 类别路径 (默认 /)
        members: JSON 数组，每个元素 {"name": "...", "type": "...", "comment": "..."}
    """
    if not name:
        return _make_error("name is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()
    cat_path = CategoryPath(category)

    # Parse members
    member_list = []
    if members:
        try:
            member_list = json.loads(members)
        except json.JSONDecodeError as e:
            return _make_error(f"Invalid members JSON: {str(e)}")

    # Create union
    union = UnionDataType(cat_path, name)

    # Add members
    for i, member in enumerate(member_list):
        member_type_str = member.get("type", "")
        if not member_type_str:
            return _make_error(f"Member {i} missing 'type'")

        member_dt, err = _resolve_datatype_safe(dtm, member_type_str)
        if err:
            return _make_error(f"Member {i}: {err.get('error', 'unknown error')}")

        member_name = member.get("name", "")
        member_comment = member.get("comment", "")
        union.add(member_dt, member_name, member_comment)

    # Add to DTM
    tx_id = prog.startTransaction("Create Union")
    try:
        result = dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to create union: {str(e)}")

    # Build member info for response
    member_info = []
    for i in range(result.getNumComponents()):
        comp = result.getComponent(i)
        member_info.append({
            "name": comp.getFieldName() or f"member_{i}",
            "type": str(comp.getDataType()),
            "size": comp.getLength()
        })

    return _make_success({
        "name": result.getName(),
        "path": result.getPathName(),
        "category": str(result.getCategoryPath()),
        "size": result.getLength(),
        "member_count": result.getNumComponents(),
        "members": member_info,
        "type": "create_union"
    })


@route("/api/datatype/create/funcdef")
def create_funcdef(state, name="", return_type="void", params="", category="/", calling_convention=""):
    """
    创建函数定义（函数指针类型）。

    路由: GET /api/datatype/create/funcdef?name=CallbackFn&return_type=int&params=[{"name":"ctx","type":"void *"}]

    参数:
        name: 函数定义名称
        return_type: 返回类型 (默认 void)
        params: JSON 数组，每个元素 {"name": "...", "type": "...", "comment": "..."}
        category: 类别路径 (默认 /)
        calling_convention: 调用约定 (可选，如 "__stdcall", "__cdecl")
    """
    if not name:
        return _make_error("name is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()
    cat_path = CategoryPath(category)

    # Resolve return type
    ret_dt, err = _resolve_datatype_safe(dtm, return_type)
    if err:
        return err

    # Parse parameters
    param_list = []
    if params:
        try:
            param_list = json.loads(params)
        except json.JSONDecodeError as e:
            return _make_error(f"Invalid params JSON: {str(e)}")

    # Create function definition
    funcdef = FunctionDefinitionDataType(cat_path, name)
    funcdef.setReturnType(ret_dt)

    # Set parameters
    param_defs = []
    for i, p in enumerate(param_list):
        param_type_str = p.get("type", "")
        if not param_type_str:
            return _make_error(f"Parameter {i} missing 'type'")

        param_dt, err = _resolve_datatype_safe(dtm, param_type_str)
        if err:
            return _make_error(f"Parameter {i}: {err.get('error', 'unknown error')}")

        param_name = p.get("name", f"param_{i}")
        param_comment = p.get("comment", "")
        param_defs.append(ParameterDefinitionImpl(param_name, param_dt, param_comment))

    if param_defs:
        funcdef.setArguments(param_defs)

    # Set calling convention if specified
    if calling_convention:
        funcdef.setCallingConvention(calling_convention)

    # Add to DTM
    tx_id = prog.startTransaction("Create FuncDef")
    try:
        result = dtm.addDataType(funcdef, DataTypeConflictHandler.REPLACE_HANDLER)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to create funcdef: {str(e)}")

    # Build param info for response
    args = result.getArguments()
    param_info = []
    for arg in args:
        param_info.append({
            "name": arg.getName(),
            "type": str(arg.getDataType()),
        })

    return _make_success({
        "name": result.getName(),
        "path": result.getPathName(),
        "category": str(result.getCategoryPath()),
        "return_type": str(result.getReturnType()),
        "calling_convention": result.getCallingConventionName() or "default",
        "param_count": len(param_info),
        "params": param_info,
        "signature": result.getPrototypeString(),
        "type": "create_funcdef"
    })


# ============================================================
# Part C: 类型管理 API
# ============================================================

@route("/api/datatype/struct/field/add")
def struct_field_add(state, struct="", type="", name="", comment="", at=-1):
    """
    添加结构体字段。

    路由: GET /api/datatype/struct/field/add?struct=MyStruct&type=int&name=new_field
          GET /api/datatype/struct/field/add?struct=MyStruct&type=char *&name=ptr&at=0

    参数:
        struct: 结构体名称或路径
        type: 字段类型
        name: 字段名称
        comment: 字段注释 (可选)
        at: 插入位置索引 (可选，-1=追加到末尾)
    """
    if not struct:
        return _make_error("struct is required")
    if not type:
        return _make_error("type is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()

    # Resolve struct
    struct_dt, err = _resolve_datatype_safe(dtm, struct)
    if err:
        return err

    from ghidra.program.model.data import Structure
    if not isinstance(struct_dt, Structure):
        return _make_error(f"'{struct}' is not a structure type")

    # Resolve field type
    field_dt, err = _resolve_datatype_safe(dtm, type)
    if err:
        return err

    at = int(at)

    tx_id = prog.startTransaction("Add Struct Field")
    try:
        if at >= 0 and at < struct_dt.getNumComponents():
            # Insert at specific position
            struct_dt.insert(at, field_dt, -1, name, comment)
            ordinal = at
        else:
            # Append to end
            struct_dt.add(field_dt, name, comment)
            ordinal = struct_dt.getNumComponents() - 1
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to add field: {str(e)}")

    comp = struct_dt.getComponent(ordinal)

    return _make_success({
        "struct": struct,
        "struct_path": struct_dt.getPathName(),
        "field": name or f"field_{ordinal}",
        "ordinal": ordinal,
        "offset": comp.getOffset(),
        "type": type,
        "struct_size": struct_dt.getLength(),
        "action": "add_field"
    })


@route("/api/datatype/struct/field/delete")
def struct_field_delete(state, struct="", field=""):
    """
    删除结构体字段。

    路由: GET /api/datatype/struct/field/delete?struct=MyStruct&field=old_field
          GET /api/datatype/struct/field/delete?struct=MyStruct&field=2

    参数:
        struct: 结构体名称或路径
        field: 字段名称或索引
    """
    if not struct:
        return _make_error("struct is required")
    if not field and field != 0:
        return _make_error("field is required (index or name)")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()

    # Resolve struct
    struct_dt, err = _resolve_datatype_safe(dtm, struct)
    if err:
        return err

    from ghidra.program.model.data import Structure
    if not isinstance(struct_dt, Structure):
        return _make_error(f"'{struct}' is not a structure type")

    # Find field ordinal
    ordinal, err = _resolve_field_ordinal(struct_dt, field)
    if err:
        return err

    comp = struct_dt.getComponent(ordinal)
    deleted_name = comp.getFieldName() or f"field_{ordinal}"
    deleted_type = str(comp.getDataType())

    tx_id = prog.startTransaction("Delete Struct Field")
    try:
        struct_dt.delete(ordinal)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to delete field: {str(e)}")

    return _make_success({
        "struct": struct,
        "struct_path": struct_dt.getPathName(),
        "deleted_field": deleted_name,
        "deleted_ordinal": ordinal,
        "deleted_type": deleted_type,
        "new_field_count": struct_dt.getNumComponents(),
        "new_struct_size": struct_dt.getLength(),
        "action": "delete_field"
    })


@route("/api/datatype/struct/field/modify")
def struct_field_modify(state, struct="", field="", new_name="", new_type="", new_comment=""):
    """
    修改结构体字段。

    路由: GET /api/datatype/struct/field/modify?struct=MyStruct&field=old_name&new_name=new_name
          GET /api/datatype/struct/field/modify?struct=MyStruct&field=0&new_type=int&new_comment=Updated

    参数:
        struct: 结构体名称或路径
        field: 字段名称或索引
        new_name: 新字段名 (可选)
        new_type: 新类型 (可选)
        new_comment: 新注释 (可选, 传空字符串删除注释)
    """
    if not struct:
        return _make_error("struct is required")
    if not field and field != 0:
        return _make_error("field is required (index or name)")
    if not new_name and not new_type and new_comment is None:
        return _make_error("At least one of new_name, new_type, or new_comment is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()

    # Resolve struct
    struct_dt, err = _resolve_datatype_safe(dtm, struct)
    if err:
        return err

    from ghidra.program.model.data import Structure
    if not isinstance(struct_dt, Structure):
        return _make_error(f"'{struct}' is not a structure type")

    # Find field ordinal
    ordinal, err = _resolve_field_ordinal(struct_dt, field)
    if err:
        return err

    comp = struct_dt.getComponent(ordinal)
    old_name = comp.getFieldName() or f"field_{ordinal}"
    old_type = str(comp.getDataType())
    old_comment = comp.getComment() or ""

    # Determine new values
    final_name = new_name if new_name else old_name
    final_comment = new_comment if new_comment is not None else old_comment

    if new_type:
        final_dt, err = _resolve_datatype_safe(dtm, new_type)
        if err:
            return err
    else:
        final_dt = comp.getDataType()

    tx_id = prog.startTransaction("Modify Struct Field")
    try:
        struct_dt.replace(ordinal, final_dt, final_dt.getLength(), final_name, final_comment)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to modify field: {str(e)}")

    return _make_success({
        "struct": struct,
        "struct_path": struct_dt.getPathName(),
        "ordinal": ordinal,
        "old_name": old_name,
        "new_name": final_name,
        "old_type": old_type,
        "new_type": str(final_dt),
        "old_comment": old_comment,
        "new_comment": final_comment,
        "action": "modify_field"
    })


@route("/api/datatype/enum/member/add")
def enum_member_add(state, enum="", name="", value=0):
    """
    添加枚举成员。

    路由: GET /api/datatype/enum/member/add?enum=Status&name=PENDING&value=2

    参数:
        enum: 枚举名称或路径
        name: 成员名称
        value: 成员值
    """
    if not enum:
        return _make_error("enum is required")
    if not name:
        return _make_error("name is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()

    # Resolve enum
    enum_dt, err = _resolve_datatype_safe(dtm, enum)
    if err:
        return err

    from ghidra.program.model.data import Enum
    if not isinstance(enum_dt, Enum):
        return _make_error(f"'{enum}' is not an enum type")

    value = int(value)

    tx_id = prog.startTransaction("Add Enum Member")
    try:
        enum_dt.add(name, value)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to add enum member: {str(e)}")

    return _make_success({
        "enum": enum,
        "enum_path": enum_dt.getPathName(),
        "added_name": name,
        "added_value": value,
        "member_count": len(list(enum_dt.getNames())),
        "action": "add_enum_member"
    })


@route("/api/datatype/enum/member/delete")
def enum_member_delete(state, enum="", name=""):
    """
    删除枚举成员。

    路由: GET /api/datatype/enum/member/delete?enum=Status&name=DEPRECATED

    参数:
        enum: 枚举名称或路径
        name: 成员名称
    """
    if not enum:
        return _make_error("enum is required")
    if not name:
        return _make_error("name is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()

    # Resolve enum
    enum_dt, err = _resolve_datatype_safe(dtm, enum)
    if err:
        return err

    from ghidra.program.model.data import Enum
    if not isinstance(enum_dt, Enum):
        return _make_error(f"'{enum}' is not an enum type")

    # Check if member exists
    try:
        old_value = enum_dt.getValue(name)
    except Exception:
        available = list(enum_dt.getNames())
        return _make_error(f"Enum member not found: {name}. Available: {available}")

    tx_id = prog.startTransaction("Delete Enum Member")
    try:
        enum_dt.remove(name)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to delete enum member: {str(e)}")

    return _make_success({
        "enum": enum,
        "enum_path": enum_dt.getPathName(),
        "deleted_name": name,
        "deleted_value": old_value,
        "member_count": len(list(enum_dt.getNames())),
        "action": "delete_enum_member"
    })


@route("/api/datatype/delete")
def delete_datatype(state, path="", name=""):
    """
    删除数据类型。

    路由: GET /api/datatype/delete?path=/MyCategory/MyStruct
          GET /api/datatype/delete?name=OldStruct

    参数:
        path: 数据类型路径 (与 name 二选一)
        name: 数据类型名称 (与 path 二选一)
    """
    if not path and not name:
        return _make_error("Must provide 'path' or 'name'")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()

    # Resolve datatype
    dt, err = _resolve_datatype_safe(dtm, path or name)
    if err:
        return err

    dt_name = dt.getName()
    dt_path = dt.getPathName()
    dt_category = str(dt.getCategoryPath())

    tx_id = prog.startTransaction("Delete DataType")
    try:
        dtm.remove(dt, ConsoleTaskMonitor())
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to delete datatype: {str(e)}")

    return _make_success({
        "deleted_name": dt_name,
        "deleted_path": dt_path,
        "deleted_category": dt_category,
        "action": "delete_datatype"
    })


@route("/api/datatype/copy")
def copy_datatype(state, source="", dest_category="/", new_name=""):
    """
    复制数据类型到其他类别。

    路由: GET /api/datatype/copy?source=/Point&dest_category=/Geometry&new_name=Point2D

    参数:
        source: 源数据类型路径或名称
        dest_category: 目标类别路径
        new_name: 新名称 (可选，不填则保持原名)
    """
    if not source:
        return _make_error("source is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()

    # Resolve source
    src_dt, err = _resolve_datatype_safe(dtm, source)
    if err:
        return err

    dest_cat = CategoryPath(dest_category)

    tx_id = prog.startTransaction("Copy DataType")
    try:
        # Create a copy
        copied = src_dt.copy(dtm)
        copied.setCategoryPath(dest_cat)
        if new_name:
            copied.setName(new_name)

        result = dtm.addDataType(copied, DataTypeConflictHandler.REPLACE_HANDLER)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to copy datatype: {str(e)}")

    return _make_success({
        "source_path": src_dt.getPathName(),
        "new_path": result.getPathName(),
        "new_name": result.getName(),
        "new_category": str(result.getCategoryPath()),
        "action": "copy_datatype"
    })


@route("/api/datatype/move")
def move_datatype(state, source="", dest_category="/"):
    """
    移动数据类型到其他类别。

    路由: GET /api/datatype/move?source=/Point&dest_category=/Geometry

    参数:
        source: 源数据类型路径或名称
        dest_category: 目标类别路径
    """
    if not source:
        return _make_error("source is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()

    # Resolve source
    src_dt, err = _resolve_datatype_safe(dtm, source)
    if err:
        return err

    old_path = src_dt.getPathName()
    old_category = str(src_dt.getCategoryPath())
    dest_cat = CategoryPath(dest_category)

    tx_id = prog.startTransaction("Move DataType")
    try:
        src_dt.setCategoryPath(dest_cat)
        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        return _make_error(f"Failed to move datatype: {str(e)}")

    return _make_success({
        "name": src_dt.getName(),
        "old_path": old_path,
        "new_path": src_dt.getPathName(),
        "old_category": old_category,
        "new_category": str(src_dt.getCategoryPath()),
        "action": "move_datatype"
    })


# ============================================================
# Part D: C 头文件解析 API
# ============================================================

@route("/api/datatype/parse/c")
def parse_c_code(state, code="", category="/"):
    """
    解析 C 代码创建数据类型。

    路由: GET /api/datatype/parse/c?code=typedef%20struct%20{%20int%20x;%20}%20Point;

    参数:
        code: C 代码（URL 编码）
        category: 类别路径 (默认 /)

    示例 code:
        typedef struct { int x; int y; } Point;
        struct Node { int value; struct Node *next; };
        enum Color { RED, GREEN, BLUE };
    """
    if not code:
        return _make_error("code is required")

    prog, err = _get_program(state)
    if err:
        return err

    dtm = prog.getDataTypeManager()

    # Get initial type count
    initial_types = set()
    for dt in dtm.getAllDataTypes():
        initial_types.add(dt.getPathName())

    tx_id = prog.startTransaction("Parse C Code")
    try:
        from ghidra.app.util.cparser.C import CParser
        from ghidra.program.model.data import DataTypeConflictHandler

        # 初始化 CParser
        parser = CParser(dtm)

        # 直接传入 C 代码字符串
        parsed_dt = parser.parse(code)

        # 将解析出的类型添加到 Manager 中
        # 使用 REPLACE_EXISTING 以支持修改已存在的类型
        if parsed_dt is not None:
            dtm.addDataType(parsed_dt, DataTypeConflictHandler.REPLACE_EXISTING_DATA_TYPE)

        prog.endTransaction(tx_id, True)
    except Exception as e:
        prog.endTransaction(tx_id, False)
        error_msg = str(e)
        # Parse error messages are often verbose, try to extract key info
        if "line" in error_msg.lower():
            return _make_error(f"Parse error: {error_msg}")
        return _make_error(f"Failed to parse C code: {error_msg}")

    # Find newly added types
    new_types = []
    for dt in dtm.getAllDataTypes():
        path = dt.getPathName()
        if path not in initial_types:
            new_types.append({
                "name": dt.getName(),
                "path": path,
                "category": str(dt.getCategoryPath()),
                "size": dt.getLength(),
                "kind": dt.__class__.__name__.replace("DataType", "")
            })

    return _make_success({
        "parsed_code": code[:200] + ("..." if len(code) > 200 else ""),
        "types_created": len(new_types),
        "new_types": new_types,
        "action": "parse_c"
    })


# ============================================================
# 数据类型信息查询 API
# ============================================================

@route("/api/datatype/archives")
def list_archives(state):
    """
    列出所有可用的数据类型库（DataTypeManager）。

    路由: GET /api/datatype/archives

    返回:
        archives: 数据类型库列表，包含名称、类型数量、类别数量等信息
    """
    dtms = _get_all_dtms(state)

    archives = []
    for name, dtm in dtms:
        try:
            # Count types and categories
            type_count = 0
            for _ in dtm.getAllDataTypes():
                type_count += 1

            cat_count = dtm.getCategoryCount() if hasattr(dtm, 'getCategoryCount') else 0

            archives.append({
                "name": name,
                "type_count": type_count,
                "category_count": cat_count,
                "is_modifiable": dtm.isUpdatable() if hasattr(dtm, 'isUpdatable') else True,
            })
        except Exception as e:
            archives.append({
                "name": name,
                "type_count": -1,
                "error": str(e)
            })

    return _make_success({
        "archive_count": len(archives),
        "archives": archives
    })


@route("/api/datatype/info")
def get_datatype_info(state, path="", name="", archive=""):
    """
    获取数据类型的详细信息。

    路由: GET /api/datatype/info?path=/MyStruct
          GET /api/datatype/info?name=MyStruct
          GET /api/datatype/info?name=size_t&archive=BuiltInTypes

    参数:
        path: 数据类型路径 (与 name 二选一)
        name: 数据类型名称 (与 path 二选一)
        archive: 数据类型库名称 (可选，默认搜索所有库)
    """
    if not path and not name:
        return _make_error("Must provide 'path' or 'name'")

    # If archive specified, search only in that archive
    if archive:
        dtm, err = _get_dtm_by_name(state, archive)
        if err:
            return err
        dtms_to_search = [(archive, dtm)]
    else:
        # Search all archives
        dtms_to_search = _get_all_dtms(state)

    # Try to find the datatype in any of the DTMs
    dt = None
    found_archive = None
    search_key = path or name

    for arch_name, dtm in dtms_to_search:
        try:
            resolved, _ = _resolve_datatype_safe(dtm, search_key)
            if resolved:
                dt = resolved
                found_archive = arch_name
                break
        except Exception:
            continue

    if dt is None:
        return _make_error(f"Data type not found: {search_key}")

    result = {
        "name": dt.getName(),
        "path": dt.getPathName(),
        "category": str(dt.getCategoryPath()),
        "archive": found_archive,
        "size": dt.getLength(),
        "description": dt.getDescription() or "",
        "display_name": dt.getDisplayName(),
        "kind": dt.__class__.__name__.replace("DataType", "")
    }

    # Add structure-specific info
    # 注意: TypeDef 而不是 Typedef（大写 D）
    from ghidra.program.model.data import Structure, Enum, Union, TypeDef, FunctionDefinition

    if isinstance(dt, Structure):
        fields = []
        for i in range(dt.getNumComponents()):
            comp = dt.getComponent(i)
            fields.append({
                "ordinal": i,
                "name": comp.getFieldName() or f"field_{i}",
                "type": str(comp.getDataType()),
                "offset": comp.getOffset(),
                "size": comp.getLength(),
                "comment": comp.getComment() or ""
            })
        result["fields"] = fields
        result["field_count"] = len(fields)
        result["is_packed"] = dt.isPackingEnabled() if hasattr(dt, 'isPackingEnabled') else False

    elif isinstance(dt, Enum):
        members = []
        for member_name in dt.getNames():
            members.append({
                "name": member_name,
                "value": dt.getValue(member_name)
            })
        result["members"] = members
        result["member_count"] = len(members)

    elif isinstance(dt, Union):
        members = []
        for i in range(dt.getNumComponents()):
            comp = dt.getComponent(i)
            members.append({
                "ordinal": i,
                "name": comp.getFieldName() or f"member_{i}",
                "type": str(comp.getDataType()),
                "size": comp.getLength(),
                "comment": comp.getComment() or ""
            })
        result["members"] = members
        result["member_count"] = len(members)

    elif isinstance(dt, TypeDef):
        result["base_type"] = str(dt.getDataType())

    elif isinstance(dt, FunctionDefinition):
        result["return_type"] = str(dt.getReturnType())
        result["calling_convention"] = dt.getCallingConventionName() or "default"
        params = []
        for arg in dt.getArguments():
            params.append({
                "name": arg.getName(),
                "type": str(arg.getDataType())
            })
        result["params"] = params
        result["signature"] = dt.getPrototypeString()

    return _make_success(result)


@route("/api/datatype/list")
def list_datatypes(state, category="/", q="", limit=100, archive=""):
    """
    列出类别下的数据类型。

    路由: GET /api/datatype/list
          GET /api/datatype/list?category=/MyTypes
          GET /api/datatype/list?q=*Struct*&limit=50
          GET /api/datatype/list?archive=BuiltInTypes
          GET /api/datatype/list?archive=all  (搜索所有库)

    参数:
        category: 类别路径 (默认 / 表示所有)
        q: 名称过滤（支持通配符 * ?）
        limit: 最大返回数量 (默认 100)
        archive: 数据类型库名称 (可选，默认当前程序；'all' 搜索所有库)
    """
    limit = int(limit)

    import fnmatch

    # Determine which DTMs to search
    if archive.lower() == "all":
        dtms_to_search = _get_all_dtms(state)
    elif archive:
        dtm, err = _get_dtm_by_name(state, archive)
        if err:
            return err
        dtms_to_search = [(archive, dtm)]
    else:
        # Default to program's DTM
        prog, err = _get_program(state)
        if err:
            return err
        dtm = prog.getDataTypeManager()
        dtms_to_search = [(prog.getName(), dtm)]

    # Determine if using wildcard
    use_wildcard = '*' in q or '?' in q
    q_lower = q.lower() if q else ""

    results = []
    for arch_name, dtm in dtms_to_search:
        if len(results) >= limit:
            break

        for dt in dtm.getAllDataTypes():
            if len(results) >= limit:
                break

            # Filter by category
            dt_category = str(dt.getCategoryPath())
            if category != "/" and not dt_category.startswith(category):
                continue

            # Filter by name
            name = dt.getName()
            if q:
                if use_wildcard:
                    if not fnmatch.fnmatch(name.lower(), q_lower):
                        continue
                else:
                    if q_lower not in name.lower():
                        continue

            results.append({
                "name": name,
                "path": dt.getPathName(),
                "category": dt_category,
                "archive": arch_name,
                "size": dt.getLength(),
                "kind": dt.__class__.__name__.replace("DataType", "")
            })

    return _make_success({
        "archive": archive if archive else "program",
        "category": category,
        "query": q,
        "count": len(results),
        "limit": limit,
        "datatypes": results
    })


# ============================================================
# 数据类型导出 API
# ============================================================

@route("/api/datatype/export/c")
def export_c_header(state, category="/"):
    """
    导出当前程序的数据类型为 C header 格式。

    路由: GET /api/datatype/export/c
          GET /api/datatype/export/c?category=/MyTypes

    参数:
        category: 类别路径 (默认 / 表示全部)

    返回:
        c_header: C header 格式的类型定义

    注意:
        - 函数声明不会被导出（Ghidra 限制），除非是 function pointer typedef
        - 导出内容包括 struct, enum, typedef, union 等
    """
    prog, err = _get_program(state)
    if err:
        return err
    dtm = prog.getDataTypeManager()

    sw = StringWriter()
    dtw = DataTypeWriter(dtm, sw)
    monitor = ConsoleTaskMonitor()

    exported_types = []

    try:
        if category != "/":
            # 导出指定类别
            cat_path = CategoryPath(category)
            cat = dtm.getCategory(cat_path)
            if cat is None:
                return _make_error(f"Category not found: {category}")
            dtw.write(cat, monitor)
            # 收集导出的类型名
            for dt in cat.getDataTypes():
                exported_types.append(dt.getName())

        else:
            # 导出全部
            dtw.write(dtm, monitor)
            exported_types = ["(all)"]

    except Exception as e:
        return _make_error(f"Export failed: {str(e)}")

    c_header = sw.toString()

    return _make_success({
        "c_header": c_header,
        "category": category,
        "types": exported_types,
        "length": len(c_header),
        "action": "export_c_header"
    })
