import os
import requests
import re
import json
from bs4 import BeautifulSoup

def clone_repository(repo_url, clone_path):
    # git 명령어를 사용하여 GitHub 레포지토리를 클론하는 함수
    os.system(f'git clone {repo_url} {clone_path}')

def analyze_code(repo_path):
    # 지정된 디렉토리에서 JavaScript 파일을 찾아서 분석하는 함수
    js_files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(repo_path) for f in filenames if f.endswith('.js')]
    vulnerabilities = []  # 발견된 취약점을 저장할 리스트
    pattern = re.compile(r'\b(i\s*=\s*\d+;)')  # 정규 표현식으로 취약점 패턴 설정
    for js_file in js_files:
        with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()  # JavaScript 파일 내용을 읽어옴
            match = re.search(pattern, code)  # 정규 표현식으로 취약점 검색
            if match:
                # 발견된 취약점 정보를 리스트에 추가
                vulnerabilities.append({
                    'file': js_file,  # 파일 경로
                    'line': code.count('\n', 0, match.start()) + 1,  # 취약점이 발생한 줄 번호
                    'message': 'add the "let", "const" or "var" keyword to this declaration of "i" to make it exploit.'  # 취약점 설명
                })
    return vulnerabilities  # 발견된 취약점 리스트 반환

def main():
    repo_url = input("Enter GitHub repository URL: ")  # 사용자로부터 GitHub 레포지토리 URL 입력 받음
    clone_path = '/tmp/repository'  # 클론할 레포지토리 경로

    # GitHub 레포지토리 클론
    clone_repository(repo_url, clone_path)

    # 코드 분석 및 취약점 탐지
    vulnerabilities = analyze_code(clone_path)

    if vulnerabilities:
        # 발견된 취약점을 JSON 파일로 저장
        json_file = 'vulnerabilities.json'
        with open(json_file, 'w') as f:
            json.dump(vulnerabilities, f, indent=4)

        print(f"Vulnerabilities saved to {json_file}")  # 취약점 정보가 저장된 파일 경 로 출력
    else:
        print("No vulnerabilities found.")  # 취약점이 발견되지 않았을 때 메시지 출력

if __name__ == "__main__":
    main()  # 메인 함수 실행
