import json
import sys
import re
from pycparser import parse_file, c_ast

# JSON 변환 시 예외 처리 클래스
class CJsonError(Exception):
    pass

# 함수 결과를 캐시하는 데코레이터
def memodict(fn):
    class memodict(dict):
        def __missing__(self, key):
            ret = self[key] = fn(key)
            return ret
    return memodict().__getitem__

# 타입 이름을 재귀적으로 추출
def get_type_name(type_decl):
    if isinstance(type_decl, c_ast.TypeDecl):
        return get_type_name(type_decl.type)
    elif isinstance(type_decl, c_ast.IdentifierType):
        return ' '.join(type_decl.names)
    elif isinstance(type_decl, c_ast.PtrDecl):
        return f"{get_type_name(type_decl.type)}*"
    else:
        return 'UnknownType'

# if 문의 개수를 재귀적으로 계산
def count_if_statements(node):
    count = 0
    if isinstance(node, c_ast.If):
        count += 1
    for _, child in node.children():
        count += count_if_statements(child)
    return count

# 함수 정의에서 정보 추출
def extract_func_info(func_def):
    func_info = {
        'return_type': get_type_name(func_def.decl.type),
        'name': func_def.decl.name,
        'parameters': [],
        'if_count': count_if_statements(func_def.body)
    }

    if hasattr(func_def.decl.type, 'args') and func_def.decl.type.args:
        for param in func_def.decl.type.args.params:
            param_type = get_type_name(param.type)
            param_name = param.name
            func_info['parameters'].append({'type': param_type, 'name': param_name})

    return func_info

# AST를 딕셔너리 형태로 변환
def to_dict(node):
    klass = node.__class__
    result = {'_nodetype': klass.__name__}

    for attr in klass.attr_names:
        result[attr] = getattr(node, attr)

    if isinstance(node, c_ast.FuncDef):
        result['function_details'] = extract_func_info(node)
    else:
        for child_name, child in node.children():
            child_data = to_dict(child)
            match = re.match(r'(.*)\[\d+\]', child_name)
            if match:
                array_name = match.groups()[0]
                result.setdefault(array_name, []).append(child_data)
            else:
                result[child_name] = child_data

    return result

# 파일을 파싱하여 AST를 딕셔너리로 변환
def file_to_dict(filename):
    ast = parse_file(filename, use_cpp=True)
    return to_dict(ast)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        ast_dict = file_to_dict(sys.argv[1])  # 명령줄 인자로 받은 파일을 파싱
        func_count = sum(1 for item in ast_dict.get('ext', []) if item.get('_nodetype') == 'FuncDef')  # 함수 개수 계산
        print(json.dumps(ast_dict, indent=4))  # 변환된 딕셔너리를 JSON으로 출력
        print(f"Function Count: {func_count}")  # 함수 개수 출력
    else:
        print("Please provide a filename as argument")  # 파일 이름을 인자로 제공하지  않은 경우 메시지 출력
