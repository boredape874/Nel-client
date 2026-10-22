# BDS 버전 분석 자동화

BDS와 Minecraft Windows 클라이언트는 별도 바이너리다. 이 workflow는 공식 BDS Windows/Linux 릴리즈를 대상으로 하고, 클라이언트 호환성 판정으로 사용하지 않는다.

## 실행

GitHub에서 `Actions → BDS binary analysis → Run workflow`를 연다.

1. `detect`: 공식 배포 메타데이터와 새 버전 여부만 확인한다.
2. `triage`: 구/신 BDS를 받아 해시·실행 파일 구조·등록한 BDS 패턴을 비교한다.
3. `deep`: 고정된 Ghidra/Ghidriff 분석 이미지를 빌드해 함수 차이 보고서를 만든다.

먼저 `detect`를 실행하고, 정확한 기존 기준 버전이 있을 때만 triage/deep를 선택한다. 구버전 입력이 없으면 임의 버전으로 대체하지 않고 BLOCKED로 보고한다. 기본 예약 실행은 detect 모드이며 새 버전을 지원 버전으로 자동 승인하지 않는다.

## 예약 모드 설정

`Settings → Secrets and variables → Actions → Variables`에 필요할 때 다음 값을 둔다.

| Variable | 설명 |
| --- | --- |
| `BDS_BASELINE_VERSION` | 비교에 사용할 정확한 기존 BDS 버전 |
| `BDS_AUTO_MODE` | `detect`, `triage`, `deep`; 기본은 detect |
| `BDS_PLATFORM` | `windows` 또는 `linux` |
| `BDS_CHANNEL` | `release` 또는 `preview` |

기본 `detect`는 BDS 바이너리를 다운로드하거나 Ghidra를 실행하지 않는다. triage/deep는 Actions 시간과 저장공간을 사용한다.

## 보고서 해석

- ZIP SHA256과 추출 실행 파일 SHA256은 구분한다.
- 패턴 후보 하나는 함수 의미나 ABI 호환성을 입증하지 않는다.
- deep diff가 끝나도 수동 검토가 필요하며, 실제 BDS 실행 테스트 결과와는 별개다.
- 이 자동화는 BDS를 GitHub에서 상시 서버로 호스팅하지 않는다.
- 공식 BDS 원본·PDB·분석 DB는 저장소에 커밋하지 않는다. 보고서 artifact는 저장소 접근 정책에 맞춰 보관한다.
