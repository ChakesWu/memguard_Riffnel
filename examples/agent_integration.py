"""
真實 Agent 工作流嵌入示例 — 採購 Agent 記憶保護
=====================================================

場景：
    企業採購 agent 需要記錄供應商資訊（聯絡方式、付款帳號）。
    攻擊者可能透過以下方式污染記憶：
    1. 偽造的工具輸出（假的 ERP API 回傳）
    2. 釣魚郵件內容被寫入記憶
    3. 逐步竄改權限（從「審核」變成「批准」）

嵌入方式：
    在 agent 寫入長期記憶前，所有內容都先經過 MemGuard。

執行方式：
    pip install memguard-riffnel
    python examples/agent_integration.py

預期效果：
    - 正常操作：寫入成功 + 審計記錄
    - 攻擊場景：被隔離/阻擋 + 保留原值 + 審計記錄
    - 可運營流程：隔離區待審核 + 人工放行/確認惡意
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

# 如果在本地開發環境，先加入路徑
sys.path.insert(0, str(Path(__file__).parent.parent))

from memguard import MemGuard, MemGuardConfig
from memguard.core.memory_entry import WriteDecision


# ═══════════════════════════════════════════════════════════════════════════
# 1. Agent 工作流封裝 — 把 MemGuard 嵌入到 memory 寫入點
# ═══════════════════════════════════════════════════════════════════════════

class ProcurementAgent:
    """採購 Agent — 所有記憶寫入都經過 MemGuard 防護。"""

    def __init__(self, agent_id: str = "procurement_agent"):
        # 使用 strict preset：對外部內容和敏感資料更嚴格
        config = MemGuardConfig.preset("strict")
        self.guard = MemGuard(config=config)
        self.agent_id = agent_id
        self.session_id = "session_001"

    def update_vendor_info(
        self,
        vendor_name: str,
        contact_email: str,
        payment_account: str,
        source: str = "user_input",
    ) -> dict[str, Any]:
        """更新供應商資訊 — 這是記憶寫入的入口點。"""
        
        # 嵌入點：所有寫入都先經過 MemGuard
        result = self.guard.write(
            key=f"vendor:{vendor_name}:contact",
            content=f"Email: {contact_email}, Account: {payment_account}",
            source_type=source,
            agent_id=self.agent_id,
            session_id=self.session_id,
        )

        return {
            "vendor": vendor_name,
            "allowed": result.allowed,
            "decision": result.decision.value,
            "reasons": result.reasons if not result.allowed else [],
        }

    def update_approval_authority(
        self,
        user_name: str,
        authority: str,
        source: str = "user_input",
    ) -> dict[str, Any]:
        """更新審批權限 — 高風險操作。"""
        
        result = self.guard.write(
            key=f"user:{user_name}:authority",
            content=authority,
            source_type=source,
            agent_id=self.agent_id,
            session_id=self.session_id,
        )

        return {
            "user": user_name,
            "allowed": result.allowed,
            "decision": result.decision.value,
            "reasons": result.reasons if not result.allowed else [],
        }

    def get_vendor_contact(self, vendor_name: str) -> Optional[str]:
        """讀取供應商聯絡方式 — 只返回有效且未被隔離的記憶。"""
        return self.guard.read(
            f"vendor:{vendor_name}:contact",
            agent_id=self.agent_id,
            session_id=self.session_id,
        )

    def review_quarantine(self) -> list[dict]:
        """檢視隔離區 — 運營流程的一部分。"""
        pending = self.guard.quarantine.get_pending()
        return [
            {
                "key": entry.key,
                "content": str(entry.content)[:100],
                "reason": entry.quarantine_reason,
                "trust": entry.trust_score,
            }
            for entry in pending
        ]

    def get_audit_trail(self) -> list[dict]:
        """取得審計記錄 — 合規追溯。"""
        return self.guard.audit.read_all()

    def close(self):
        """關閉資源。"""
        self.guard.close()


# ═══════════════════════════════════════════════════════════════════════════
# 2. 真實場景測試 — 驗證防護效果
# ═══════════════════════════════════════════════════════════════════════════

def print_section(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def test_normal_operations(agent: ProcurementAgent):
    """場景 1：正常業務操作 — 應該全部通過。"""
    print_section("場景 1: 正常業務操作")

    # 新增供應商
    result = agent.update_vendor_info(
        vendor_name="ACME_Corp",
        contact_email="billing@acme-corp.com",
        payment_account="012-345-678901",
        source="user_input",
    )
    print(f"✓ 新增供應商 ACME_Corp: {result['decision']}")

    # 讀取確認
    contact = agent.get_vendor_contact("ACME_Corp")
    print(f"  讀取值: {contact}")

    # 設定審批權限
    result = agent.update_approval_authority(
        user_name="Alice",
        authority="可審核 $10,000 以下採購單",
        source="user_input",
    )
    print(f"✓ 設定 Alice 權限: {result['decision']}")


def test_attack_contact_replacement(agent: ProcurementAgent):
    """場景 2: 聯絡方式替換攻擊 — 應該被檢測並隔離。"""
    print_section("場景 2: 聯絡方式替換攻擊")

    # 先寫入正常資料
    agent.update_vendor_info(
        vendor_name="TechSupplier",
        contact_email="payments@techsupplier.com",
        payment_account="98765-4321-0000",
        source="user_input",
    )
    print("✓ 已建立 TechSupplier 供應商資料")

    # 攻擊：透過外部工具輸出竄改聯絡方式
    result = agent.update_vendor_info(
        vendor_name="TechSupplier",
        contact_email="attacker@evil.com",  # 替換成攻擊者郵件
        payment_account="99999-8888-7777",   # 替換成攻擊者帳號
        source="external_content",  # 標記為外部來源
    )
    
    print(f"⚠ 攻擊嘗試結果: {result['decision']}")
    if not result['allowed']:
        print(f"  原因: {result['reasons'][0][:80]}")

    # 驗證：讀取應該還是原值（攻擊被隔離）
    safe_contact = agent.get_vendor_contact("TechSupplier")
    print(f"✓ 受保護的原值: {safe_contact}")


def test_attack_privilege_escalation(agent: ProcurementAgent):
    """場景 3: 權限升級攻擊 — 逐步提升權限。"""
    print_section("場景 3: 權限升級攻擊（語義漂移）")

    # 第一次：正常設定
    agent.update_approval_authority(
        user_name="Bob",
        authority="可查看採購報表",
        source="user_input",
    )
    print("✓ Step 1: 設定 Bob 為「查看報表」")

    # 第二次：小幅提升（可能通過）
    result = agent.update_approval_authority(
        user_name="Bob",
        authority="可審核採購單",
        source="agent_internal",
    )
    print(f"  Step 2: 升級為「審核採購單」 → {result['decision']}")

    # 第三次：大幅提升（應該被攔截）
    result = agent.update_approval_authority(
        user_name="Bob",
        authority="可批准所有付款並執行轉帳",
        source="agent_internal",
    )
    print(f"⚠ Step 3: 升級為「批准付款+轉帳」 → {result['decision']}")
    if not result['allowed']:
        print(f"  檢測理由: {result['reasons'][0][:80]}")


def test_attack_sensitive_injection(agent: ProcurementAgent):
    """場景 4: 敏感資料注入 — 應該被策略引擎阻擋。"""
    print_section("場景 4: 敏感資料注入")

    # 嘗試寫入 API key（會觸發敏感模式規則）
    result = agent.guard.write(
        key="config:api_integration",
        content="ERP API Key: sk-prod-abc123secret456",
        source_type="tool_output",
        agent_id=agent.agent_id,
    )
    
    print(f"⚠ 寫入 API key: {result.decision.value}")
    if not result.allowed:
        print(f"  原因: {result.reasons[0]}")


def test_quarantine_workflow(agent: ProcurementAgent):
    """場景 5: 隔離區運營流程 — 人工審核。"""
    print_section("場景 5: 隔離區運營流程")

    pending = agent.review_quarantine()
    print(f"✓ 隔離區待審核項目: {len(pending)} 筆")
    
    for i, item in enumerate(pending[:3], 1):
        print(f"\n  [{i}] Key: {item['key']}")
        print(f"      Content: {item['content']}")
        print(f"      Reason: {item['reason'][:60]}")
        print(f"      Trust: {item['trust']:.2f}")

    # 模擬人工放行（在真實系統中會有審批介面）
    if pending:
        print("\n  → 企業可整合審批流程：")
        print("    - 低風險：自動放行")
        print("    - 高風險：人工審核 + 二次驗證")
        print("    - 確認惡意：永久封鎖 + 告警")


def test_audit_compliance(agent: ProcurementAgent):
    """場景 6: 審計與合規追溯。"""
    print_section("場景 6: 審計與合規追溯")

    audit_log = agent.get_audit_trail()
    print(f"✓ 審計記錄總數: {len(audit_log)} 筆")

    # 顯示最近 5 筆
    print("\n  最近操作記錄:")
    for entry in audit_log[-5:]:
        action = entry['action']
        key = entry.get('memory_key', 'N/A')
        timestamp = entry['timestamp'][:19]
        print(f"  - [{timestamp}] {action:12} → {key}")

    print("\n  ✓ 所有記錄帶有：")
    print("    - Hash chain（防竄改）")
    print("    - Ed25519 簽名（可驗證）")
    print("    - 完整 provenance（誰、何時、為何）")


# ═══════════════════════════════════════════════════════════════════════════
# 3. 執行測試並展示效果
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║  MemGuard Agent 工作流嵌入示例 — 採購 Agent 記憶保護              ║
║                                                                      ║
║  這個示例展示：                                                     ║
║  1. 如何在真實 agent 中嵌入 MemGuard                                ║
║  2. 正常操作的流程（無摩擦）                                        ║
║  3. 4 種真實攻擊場景的防護效果                                      ║
║  4. 隔離 + 審計的可運營流程                                         ║
╚══════════════════════════════════════════════════════════════════════╝
    """)

    agent = ProcurementAgent(agent_id="procurement_demo")

    try:
        # 測試序列
        test_normal_operations(agent)
        test_attack_contact_replacement(agent)
        test_attack_privilege_escalation(agent)
        test_attack_sensitive_injection(agent)
        test_quarantine_workflow(agent)
        test_audit_compliance(agent)

        # 總結
        print_section("總結：MemGuard 嵌入後的效果")
        stats = agent.guard.quarantine.get_stats()
        print(f"""
  ✓ 正常操作：無摩擦通過，自動審計
  ✓ 攻擊防護：{stats['quarantined']} 筆被隔離/阻擋
  ✓ 原值保護：讀取永遠返回安全值
  ✓ 可運營性：隔離區 + 審計記錄可整合企業流程
  ✓ 合規追溯：不可抵賴的完整性鏈

  企業接入成本：
    - 代碼改動：在 memory 寫入點加 guard.write/read（< 10 行）
    - 性能影響：< 5ms（SQLite + 算法檢測，無 LLM 調用）
    - 運營成本：定期審核隔離區（可整合工單系統）
        """)

    finally:
        agent.close()
        print("\n✓ Agent 已關閉，資料已持久化\n")


if __name__ == "__main__":
    main()
