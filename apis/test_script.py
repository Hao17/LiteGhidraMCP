"""
测试脚本：用于验证script.runScript()方式调用Ghidra Flat API

这个脚本将被主服务器通过script.runScript()调用，
用来测试是否能在独立脚本中直接访问currentProgram()等函数。

参数约定：
- args[0]: 结果输出文件路径（由调用者生成的临时文件路径）
- args[1:]: 其他测试参数

脚本执行完成后会将结果写入 args[0] 指定的文件。
"""

import json
import os


def test_script_args():
    """测试从runScript传入的参数"""
    result = {
        "args_test": True,
        "received_args": [],
        "errors": []
    }

    try:
        # 获取传入的参数
        args = getScriptArgs()
        if args is not None:
            result["received_args"] = list(args)
            result["args_count"] = len(args)
        else:
            result["received_args"] = None
            result["args_count"] = 0
    except NameError as e:
        result["errors"].append(f"getScriptArgs() NameError: {str(e)}")
    except Exception as e:
        result["errors"].append(f"getScriptArgs() Exception: {str(e)}")

    return result


def test_ghidra_flat_api():
    """测试Ghidra Flat API函数的直接访问"""

    result = {
        "timestamp": str(__import__("time").time()),
        "script_execution": "test_script.py via script.runScript()",
        "test_results": {},
        "errors": [],
        "context_info": {}
    }

    # Test 1: 测试currentProgram()直接调用
    try:
        prog = currentProgram()
        if prog is not None:
            result["test_results"]["currentProgram_success"] = True
            result["test_results"]["program_name"] = prog.getName()
            result["test_results"]["program_type"] = str(type(prog))
        else:
            result["test_results"]["currentProgram_success"] = False
            result["errors"].append("currentProgram() returned None")
    except NameError as e:
        result["test_results"]["currentProgram_success"] = False
        result["errors"].append(f"currentProgram() NameError: {str(e)}")
    except Exception as e:
        result["test_results"]["currentProgram_success"] = False
        result["errors"].append(f"currentProgram() Exception: {str(e)}")

    # Test 2: 测试currentAddress()直接调用
    try:
        addr = currentAddress()
        if addr is not None:
            result["test_results"]["currentAddress_success"] = True
            result["test_results"]["current_address"] = str(addr)
            result["test_results"]["address_type"] = str(type(addr))
        else:
            result["test_results"]["currentAddress_success"] = False
            result["errors"].append("currentAddress() returned None")
    except NameError as e:
        result["test_results"]["currentAddress_success"] = False
        result["errors"].append(f"currentAddress() NameError: {str(e)}")
    except Exception as e:
        result["test_results"]["currentAddress_success"] = False
        result["errors"].append(f"currentAddress() Exception: {str(e)}")

    # Test 3: 测试其他Ghidra Flat API函数
    flat_api_tests = {
        'currentLocation': 'currentLocation()',
        'currentSelection': 'currentSelection()',
        'monitor': 'monitor()',
        'state': 'state()',
        'script': 'script()'
    }

    for func_name, func_call in flat_api_tests.items():
        try:
            # 使用eval来动态调用函数
            func_result = eval(func_call)
            result["test_results"][f"{func_name}_success"] = func_result is not None
            result["test_results"][f"{func_name}_type"] = str(type(func_result))
        except NameError:
            result["test_results"][f"{func_name}_success"] = False
            result["errors"].append(f"{func_name}() not available")
        except Exception as e:
            result["test_results"][f"{func_name}_success"] = False
            result["errors"].append(f"{func_name}() error: {str(e)}")

    # Test 4: 检查全局命名空间
    try:
        available_globals = [name for name in globals().keys() if not name.startswith('_')]
        result["context_info"]["available_globals"] = available_globals
        result["context_info"]["has_ghidra_functions"] = any(
            name in available_globals for name in ['currentProgram', 'currentAddress', 'state']
        )
    except Exception as e:
        result["errors"].append(f"Failed to inspect globals: {str(e)}")

    # Test 5: 尝试访问程序的具体信息
    if result["test_results"].get("currentProgram_success"):
        try:
            prog = currentProgram()
            result["test_results"]["program_details"] = {
                "domainFile": str(prog.getDomainFile()) if prog.getDomainFile() else None,
                "executable_path": prog.getExecutablePath() if hasattr(prog, 'getExecutablePath') else "N/A",
                "language": str(prog.getLanguage()) if prog.getLanguage() else None,
                "memory_size": prog.getMemory().getSize() if prog.getMemory() else 0
            }
        except Exception as e:
            result["errors"].append(f"Failed to get program details: {str(e)}")

    return result


def test_script_communication():
    """测试脚本间通信和数据传递"""

    result = {
        "communication_test": True,
        "script_name": "test_script.py",
        "execution_method": "script.runScript()",
        "can_return_data": True
    }

    # 测试是否能返回复杂数据结构
    try:
        if currentProgram():
            result["complex_data_test"] = {
                "program_info": {
                    "name": currentProgram().getName(),
                    "size": currentProgram().getMemory().getSize()
                },
                "nested_structure": {
                    "level1": {
                        "level2": ["item1", "item2", "item3"]
                    }
                }
            }
        result["data_serialization_success"] = True
    except Exception as e:
        result["data_serialization_success"] = False
        result["error"] = str(e)

    return result


# 主要测试函数
def run_all_tests():
    """运行所有测试并返回综合结果"""

    comprehensive_result = {
        "script_execution_success": True,
        "execution_timestamp": str(__import__("time").time()),
        "tests": {}
    }

    try:
        # 运行参数测试
        comprehensive_result["tests"]["args_test"] = test_script_args()

        # 运行API测试
        comprehensive_result["tests"]["flat_api_test"] = test_ghidra_flat_api()

        # 运行通信测试
        comprehensive_result["tests"]["communication_test"] = test_script_communication()

        # 总体评估
        args_received = len(comprehensive_result["tests"]["args_test"].get("received_args", [])) > 0
        api_success = comprehensive_result["tests"]["flat_api_test"]["test_results"].get("currentProgram_success", False)
        comm_success = comprehensive_result["tests"]["communication_test"]["data_serialization_success"]

        comprehensive_result["overall_success"] = api_success and comm_success
        comprehensive_result["summary"] = {
            "args_passed": args_received,
            "flat_api_works": api_success,
            "communication_works": comm_success,
            "method_viable": api_success and comm_success
        }

    except Exception as e:
        comprehensive_result["script_execution_success"] = False
        comprehensive_result["error"] = str(e)

    return comprehensive_result


def get_result_output_path():
    """
    从脚本参数中获取结果输出文件路径。

    Returns:
        结果文件路径，如果未提供则返回 None
    """
    try:
        args = getScriptArgs()
        if args is not None and len(args) > 0:
            return args[0]
    except NameError:
        pass
    except Exception:
        pass
    return None


def write_result_to_file(result, filepath):
    """
    将结果写入指定文件。

    Args:
        result: 要写入的结果对象（会被序列化为JSON）
        filepath: 输出文件路径

    Returns:
        True 如果写入成功，否则返回错误信息
    """
    try:
        # 确保目录存在
        dir_path = os.path.dirname(filepath)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        return True
    except Exception as e:
        return f"Failed to write result: {str(e)}"


# 如果脚本被直接执行（通过runScript），运行测试
if __name__ == "__main__":
    # 运行所有测试
    test_result = run_all_tests()

    # 获取结果输出路径
    output_path = get_result_output_path()

    if output_path:
        # 如果提供了输出路径，写入文件
        write_status = write_result_to_file(test_result, output_path)
        if write_status is True:
            test_result["_output_written_to"] = output_path
            print(f"[test_script] Result written to: {output_path}")
        else:
            test_result["_output_write_error"] = write_status
            print(f"[test_script] Failed to write result: {write_status}")
            # 仍然尝试输出到控制台
            print(json.dumps(test_result, indent=2))
    else:
        # 没有提供输出路径，输出到控制台
        print("[test_script] No output path provided, printing to console:")
        print(json.dumps(test_result, indent=2))