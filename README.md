# MITRE ATT&CK

---

GitHub repository 

[https://github.com/JoWoonJi/MITRE_ATT-CK](https://github.com/JoWoonJi/MITRE_ATT-CK)


---

<aside>
💡 4조

</aside>

---

과제 정리

- [x]  침해 분석 사고 보고서 설정 후 정독
- [x]  ATT&CK 프레임워크에 매핑(침해사고에 사용된 유효한 Techniques 들을 매핑)
- [x]  침해사고 보고서에 해당되는 Tactic, Techniques 별 상세 Procedure 설명 및 정리

---

# #1. 침해 분석 사고 보고서 설정

- 곽경주 이사님께서 실시간 강의 때 소개해주신 라자루스 그룹의 침해 사고 보고서를 선정
- [BYOVD 기법으로 백신 프로그램을 무력화하는 라자루스 공격 그룹의 악성코드 감염 사례 - ASEC BLOG (ahnlab.com)](https://asec.ahnlab.com/ko/40495/)
- 정독 후 팀원끼리 과제에 대한 토론 및 방향 설정
  

---

# #2. ATT&CK 프레임워크에 매핑

- 유데미의 강의를 토대로 실습 및 매핑  **[MITRE ATT&CK Framework Essentials](https://www.udemy.com/course/mitre-attck-framework-essentials/)**

![1](https://github.com/JoWoonJi/MITRE_ATT-CK/blob/main/img/mapping.jpg)

- ATT&CK프레임 워크 기능 활용해서 lazarus group으로 매핑
- 
![1](https://github.com/JoWoonJi/MITRE_ATT-CK/blob/main/img/lazarus_group.jpg)

- navigator에서 강의에서 소개한 layer 적용해보기(공격들의 위험도 분류)
- 
![1](https://github.com/JoWoonJi/MITRE_ATT-CK/blob/main/img/navigator_application.jpg))


---

# #3. 침해사고 보고서에 해당되는 Tactic, Techniques 별 상세 Procedure 설명 및 정리

**Initial Access**
T1189 : Drive-by Compromise
INISAFECrossWebEX를 사용 중인 사용자의 PC가 해당 사이트에 웹 브라우저로 접근하게 되면, INISAFECrossWebEXSvc.exe의 취약점에 의해 악성코드 배포 사이트에서 라자루스 악성코드(SCSKAppLink.dll)가 다운로드된 후 실행된다.

**Privilege Escalation**
T1068 : Exploitation for Privilege Escalation
CVE-2021-26606 버퍼 오버플로우 취약점으로 원격에서 임의의 명령어를 전송하여 악성코드 감염 등의 피해를 유발할 수 있다.

**Execution**
T1047 : Windows Management Instrumentation
라자루스 그룹은 WMI를 사용하여 원격 시스템의 MagicLine4NX를 호출하고 악성 스레드를 인젝션하는 것으로 확인

**Lateral Movement**
T1021.001 : Remote Services: Remote Desktop Protocol
공격자는 내부 시스템에 접근하기 위해 RDP를 사용하기도 한다. 접근한 후에는 다음과 같은 악성 행위를 수행한다.
먼저, 제어권 유지를 위해 백도어를 생성하고, 백도어가 통신할 TCP 60012 포트를 호스트 방화벽에서 허용한다. 이후, 백도어 파일을 생성하고 서비스로 등록해 제어권을 유지한다.

T1021.004 : Remote Services: SSH
공격자는 내부 네트워크에 존재하는 시스템들의 SSH 서버에 root 계정으로 로그인을 시도한다.

**Defense Evasion**
T1036 : Masquerading: Masquerade Task or Service
공격자는 시스템의 보안 제품을 무력화시키기 위해 BYOVD(Bring Your Own Vulnerable Driver, 취약한 드라이버 모듈을 통한 공격) 기법을 사용한다. BYOVD는 하드웨어 공급 업체의 취약한 드라이버 모듈을 악용하는 방식의 공격으로, 드라이버의 권한을 이용하므로 커널 메모리 영역에 읽고 쓰는 것이 가능해, 보안 제품을 포함한 시스템 내 모든 모니터링 프로그램을 무력화할 수 있다.
