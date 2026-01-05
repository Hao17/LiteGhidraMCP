"""
测试脚本：用于验证script.runScript()方式调用Ghidra Flat API

这个脚本将被主服务器通过script.runScript()调用，
用来测试是否能在独立脚本中直接访问currentProgram()等函数。
"""

import json


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
        # 运行API测试
        comprehensive_result["tests"]["flat_api_test"] = test_ghidra_flat_api()

        # 运行通信测试
        comprehensive_result["tests"]["communication_test"] = test_script_communication()

        # 总体评估
        api_success = comprehensive_result["tests"]["flat_api_test"]["test_results"].get("currentProgram_success", False)
        comm_success = comprehensive_result["tests"]["communication_test"]["data_serialization_success"]

        comprehensive_result["overall_success"] = api_success and comm_success
        comprehensive_result["summary"] = {
            "flat_api_works": api_success,
            "communication_works": comm_success,
            "method_viable": api_success and comm_success
        }

    except Exception as e:
        comprehensive_result["script_execution_success"] = False
        comprehensive_result["error"] = str(e)

    return comprehensive_result


# 如果脚本被直接执行（通过runScript），运行测试
if __name__ == "__main__":
    test_result = run_all_tests()
    print(json.dumps(test_result, indent=2))