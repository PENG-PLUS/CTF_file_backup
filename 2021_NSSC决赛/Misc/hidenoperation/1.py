import pyshark
def func_s7():
    try:
        captures = pyshark.FileCapture("./s7.pcapng")#这里为文件的路径
        func_codes = {}
        for c in captures:
            for pkt in c:
                if pkt.layer_name == "s7comm":
                    if hasattr(pkt, "param_func"):#param_func功能码字段
                        func_code = pkt.param_func
                        if func_code in func_codes:
                            func_codes[func_code] += 1
                        else:
                            func_codes[func_code] = 1
        print(func_codes)
    except Exception as e:
        print(e)
if __name__ == '__main__':
    func_s7()