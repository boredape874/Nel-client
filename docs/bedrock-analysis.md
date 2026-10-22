# BDS / Minecraft.Windows.exe 독립 분석 자동화

서버와 게임 클라이언트를 **각각 구버전 대 신버전으로 비교**한다. BDS와 게임 EXE를 서로 같은 프로그램으로 취급하지 않는다. 기존 클라이언트 프로젝트를 서버 구동기로 전환하지 않는다.

## 구현 범위

| 워크플로 | 역할 |
|---|---|
| BDS binary analysis | 공식 BDS 링크 확인, 구·신 Windows/Linux BDS 다운로드 및 비교 |
| Minecraft Windows client analysis | 소유자가 제공한 Windows x64 게임 실행파일 두 개 비교 |
| Analysis automation CI | 오프라인 단위 테스트, actionlint, 직접 작성한 C 프로그램을 이용한 실제 ghidriff 실행 검사 |

현재는 **보고서 생성 전용**이다. 클라이언트 DLL 소스/빌드/실제 활성 시그니처가 연결되지 않았으므로 AI 패치, DLL 빌드, 게임 실행 검증, 자동 릴리즈는 하지 않는다. 항상 `compatibility=NOT_VERIFIED`, `runtime=NOT_RUN`, `build=NOT_RUN`으로 구분한다.

## 최초 설치

이 변경이 별도 브랜치/PR로 제공된 경우 먼저 CI 결과와 설정을 검토하고 기본 브랜치(main)에 병합한다. 예약 실행과 Actions 화면의 수동 실행 버튼은 기본 브랜치에 워크플로가 있어야 정상적으로 사용할 수 있다. 이 문서는 설치 안내이며 실제 BDS/게임 분석 성공 기록을 대체하지 않는다.

## 실행 모드

- `detect`: 버전/입력 메타데이터만 확인. 게임 파일 다운로드나 Ghidra 실행 없음.
- `triage`: 다운로드 및 해시 확인, 실행 영역 검사, 등록한 바이트 패턴의 후보 검색. **함수 디컴파일/함수 비교는 아님.**
- `deep`: triage 이후 digest로 고정한 Ghidra/ghidriff 컨테이너로 함수 단위 비교. 파일 해시가 동일하면 무거운 비교 생략.

초기 BDS 예약 모드는 detect, 클라이언트 예약 분석은 비활성이다. API 키나 AI 비용이 발생하는 단계는 없다. GitHub Actions 실행/보관 한도와 과금은 계정 정책에 따른다.

## 1. BDS 실행

`Actions → BDS binary analysis → Run workflow`

먼저 `mode=detect`, `new_version=latest`, `platform=windows`, `channel=release`로 최신 공식 배포 정보를 확인한다. 비교할 때는 사용하던 정확한 BDS 버전을 `old_version`에 입력하고 `triage`를 실행한다. 입력/해시 확인 후 `deep`로 함수 비교를 수행한다.

구버전 조회는 EndstoneMC/bedrock-server-data의 v2 메타데이터를 참고한다. 메타데이터 SHA256은 **ZIP 해시**이며 추출된 EXE의 해시와 구분한다. 지원 입력은 정식 `1.xx.yy` 또는 정확한 `1.xx.yy.zz`, Preview의 `1.xx.yy-preview.zz` 또는 4자리 빌드다. 정확한 4자리 빌드가 일치하지 않으면 다른 버전으로 조용히 대체하지 않는다. 공식 CDN의 구버전 파일이 삭제되면 BLOCKED다.

최신 공식 링크에 체크섬이 없으면 다운로드 후 관측한 해시를 기록한다. 이를 공식 서명이나 제작사 검증 해시라고 표현하지 않는다.

예약 설정은 `Settings → Secrets and variables → Actions → Variables`:

| Variable | 값 |
|---|---|
| BDS_BASELINE_VERSION | 사용자가 지정하는 구버전 비교 기준 |
| BDS_AUTO_MODE | detect / triage / deep. 미설정 시 detect |
| BDS_PLATFORM | windows / linux. 기본 windows |
| BDS_CHANNEL | release / preview. 기본 release |

매일 04:17 UTC(13:17 KST)에 예약되어 있다. 실제 실행 시각은 지연될 수 있다. 기준 버전은 자동 승인/승격하지 않는다. 동일 입력/소스/도구 설정의 완료 Artifact가 남아 있으면 예약 분석을 생략한다. 보관 기간(30일)이 지나면 재분석할 수 있다. 수동 실행에는 중복 생략을 적용하지 않는다.

## 2. Minecraft.Windows.exe 입력

게임 파일을 공개 저장소에 커밋하거나 공개 Release/Artifact로 배포하지 않는다. 이용 권한이 있는 구·신 게임 실행파일을 확보해 소유자의 비공개 HTTPS 스토리지에 둔다. 원격 runner가 읽을 수 있는 서명 URL 등을 사용한다. 구매/인증/암호화 우회나 비공식 Store 자동 다운로드는 구현하지 않는다.

`analysis/client-inputs.example.json`을 복사해 실제 버전, 읽기 URL, SHA256으로 채운다. 예시의 0.0.0.0과 호스트·해시는 자리표시자다.

```powershell
(Get-FileHash 'C:\path\old\Minecraft.Windows.exe' -Algorithm SHA256).Hash.ToLower()
(Get-FileHash 'C:\path\new\Minecraft.Windows.exe' -Algorithm SHA256).Hash.ToLower()
```

`Settings → Secrets and variables → Actions`에서:

| 종류 | 이름 | 값 |
|---|---|---|
| Secret | MCBE_INPUTS_JSON | 입력 예시를 실제 값으로 채운 JSON 전체 |
| Variable | MCBE_ALLOWED_HOSTS | 허용할 정확한 HTTPS 호스트. 쉼표 구분. 리다이렉트 목적지도 포함 |

매번 Secret을 수정하지 않으려면 **MCBE_INPUTS_JSON 대신** `MCBE_MANIFEST_URL` Secret으로 비공개 JSON 주소를 지정한다. 둘을 동시에 지정하면 차단한다. JSON 호스트도 허용 목록에 넣는다. 비밀 URL은 채팅·이슈·수동 실행 입력란·공개 JSON에 적지 않는다.

`Actions → Minecraft Windows client analysis → Run workflow → triage`로 시작하고, 해시·형식을 확인한 다음 deep를 실행한다. `MCBE_AUTO_MODE=triage` 또는 `deep` Variable을 지정하면 매일 04:43 UTC(13:43 KST)에 입력 manifest를 확인한다. **이 구성 자체가 새 클라이언트 EXE를 Store에서 자동 확보하는 것은 아니다.** 소유자가 manifest/파일을 갱신하거나 별도의 승인된 공급 경로를 연결해야 한다.

지원 입력은 일반 Windows x64 PE 실행파일(`format=raw`) 또는 루트에 `Minecraft.Windows.exe`가 있는 일반 ZIP(`format=zip`, `member=Minecraft.Windows.exe`)이다. ZIP의 download_sha256은 ZIP 해시, 선택적 binary_sha256은 추출된 EXE 해시다. 암호화 패키지, MSIX/AppX 설치, 메모리 덤프와 여러 모듈 묶음은 M1 미지원이다.

## 3. 상세 보고서 보호

공개 저장소에서는 기본적으로 **summary.json / summary.md만 공개**한다. URL, 원본 바이너리, Ghidra DB, 전체 디컴파일 결과는 공개 업로드하지 않는다. 요약에는 버전·파일 해시·실행 영역·등록 시그니처의 후보 위치가 포함되므로 이 정보도 비공개여야 한다면 비공개 저장소에서 실행한다.

전체 함수 차이 보고서를 공개 저장소에서 받으려면 본인 컴퓨터에서 age 키를 만든다.

```bash
age-keygen -o analysis-key.txt
```

개인키 파일은 GitHub에 올리지 않고, 출력된 `age1...` **공개 수신키만** `REPORT_AGE_RECIPIENT` Variable에 설정한다. 워크플로가 상세 JSON/Markdown/HTML을 묶어 `details.tar.gz.age`로 암호화한다. 원본 EXE/ZIP/Ghidra DB는 묶음에 포함하지 않는다.

```bash
age -d -i analysis-key.txt -o details.tar.gz details.tar.gz.age
```

비공개 저장소에서는 상세 보고서를 접근 제한된 `details.tar.gz` Artifact로 보관한다. 공개 저장소에 수신키가 없으면 상세 보고서를 업로드하지 않고 runner 종료 시 삭제한다. 나중에 필요하면 수신키를 설정한 후 수동 재실행해야 한다.

## 4. 실제 시그니처 연결

분리된 파일에 프로젝트의 실제 활성 패턴을 등록한다.

- analysis/client-signatures.json
- analysis/bds-windows-signatures.json
- analysis/bds-linux-signatures.json

형식 예시(**Minecraft 함수가 아닌 테스트 패턴**):

```json
{"id": "MyVerifiedTarget", "pattern": "48 89 ?? 90"}
```

빈 targets는 signature_coverage=0이고 검증 성공이 아니다. UNIQUE_CANDIDATE는 후보 하나를 찾았다는 의미일 뿐 ABI 호환성을 입증하지 않는다. 현재 RIP-relative 주소 해석이나 클래스 멤버/vtable 오프셋 자동 복원은 없다.

PE는 file offset, RVA, static VA를 분리하고 ELF는 정적 가상주소를 기록한다. ASLR 적용 런타임 주소가 아니다. 패턴 길이 4~512바이트, 고정 바이트 2개 이상, 최대 128개 대상이다. 후보 16개 이상은 하한만 기록하고 AMBIGUOUS로 남긴다.

## 5. 실패와 자원 제한

BLOCKED는 입력/권한/해시 등 전제 미충족, INCOMPLETE는 timeout, FAILED는 실행 실패다. 성공으로 포장하지 않는다. TRIAGE_COMPLETE_NOT_A_FUNCTION_DIFF는 빠른 파일 검사 완료일 뿐이고 DIFF_FINISHED_REVIEW_REQUIRED도 수동 검토 및 실제 게임 검증이 필요하다.

컨테이너는 네트워크 차단, 입력 읽기 전용, 권한 제거, CPU·메모리 제한으로 실행한다. Ghidriff 상한 100분, 전체 job 130분이다. 큰 게임 바이너리가 기본 runner에서 반드시 완료된다고 보장하지 않는다. 개별 함수 분석 실패/매칭 오류도 보고서를 검토해야 한다.

현재 공개 Actions 캐시에 원본 파일과 Ghidra DB를 저장하지 않는다. 따라서 완료 보고서로 실행을 생략하는 것 외에는 구버전 분석을 재활용하지 않는다. 장기 비공개 분석 DB 저장소와 대상별 정밀 분석은 후속 확장이다.

## 참고

- https://github.com/EndstoneMC/bedrock-server-data/blob/v2/scripts/update.py
- https://github.com/clearbluejar/ghidriff
- https://github.com/clearbluejar/ghidriff/pkgs/container/ghidriff
- https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow

이 도구는 분석을 연결하는 새 코드다. 외부 도구의 라이선스나 게임 이용 조건을 변경하지 않는다. AI 수정·클라이언트 DLL 빌드·실제 게임 검증·릴리즈는 별도로 구현하고 검증해야 한다.
