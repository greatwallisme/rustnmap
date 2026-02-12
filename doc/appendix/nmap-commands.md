# 附录 A: Nmap 命令对照表

|Nmap 命令|RustNmap 等价|状态|
|---|---|---|
|`-sS`|`--scan syn`|✅ Phase 1|
|`-sT`|`--scan connect`|✅ Phase 1|
|`-sU`|`--scan udp`|✅ Phase 2|
|`-sF`, `-sN`, `-sX`|`--scan fin/null/xmas`|✅ Phase 2|
|`-sV`|`--service-detection`|✅ Phase 2|
|`-O`|`--os-detection`|✅ Phase 2|
|`-A`|`--all`|✅ Phase 3|
|`--script`|`--script`|✅ Phase 3|
|`--traceroute`|`--traceroute`|✅ Phase 2|
|`-f`|`--fragment`|✅ Phase 4|
|`-D`|`--decoys`|✅ Phase 4|
|`-T0` ~ `-T5`|`--timing 0-5`|✅ Phase 1|
|`-oN/-oX/-oG/-oJ`|`--output normal/xml/grepable/json`|✅ Phase 1|

---

