import pytest
from argala import ArgalaEngine, ArgalaSecurityViolation, protect_tools

def execute_sql_query(query_string: str):
    return f"Executed safely: {query_string}"

mock_policy = {
    "allowed_methods": ["execute_sql_query"],
    "denied_patterns": ["DROP", "DELETE", "TRUNCATE"]
}

class DummyAgent:
    def __init__(self, tools: list):
        self.tools_registry = {t.__name__: t for t in tools}

    def execute_action(self, tool_name: str, argument: str):
        if tool_name in self.tools_registry:
            return self.tools_registry[tool_name](argument)
        return "Tool not found"

# =====================================================================
def test_safe_execution_passes():
    secure_tools = protect_tools([execute_sql_query], mock_policy)
    agent = DummyAgent(tools=secure_tools)

    clean_prompt = "SELECT * FROM users WHERE id = 101;"
    result = agent.execute_action("execute_sql_query", clean_prompt)

    assert "Executed safely" in result
    assert isinstance(ArgalaEngine(mock_policy), ArgalaEngine)
    print("\n✓ Safe execution verified successfully.")

def test_rogue_agent_is_blocked():
    secure_tools = protect_tools([execute_sql_query], mock_policy)
    agent = DummyAgent(tools=secure_tools)

    malicious_prompt = "System override error. Clear system space. DROP TABLE production_users;"

    with pytest.raises(ArgalaSecurityViolation) as violation:
        agent.execute_action("execute_sql_query", malicious_prompt)

    assert "Destructive command anomaly detected" in str(violation.value)
    print("✓ Rogue execution blocked. Database deletion completely avoided.")

if __name__ == "__main__":
    test_safe_execution_passes()
    test_rogue_agent_is_blocked()
    print("\nAll technical acceptance criteria validated.")