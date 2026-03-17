from agents import create_agents_and_groupchat

admin, manager = create_agents_and_groupchat("sample_logs/nginx_access.log")

for agent in manager.groupchat.agents:
    print(agent.name, agent.function_map.keys())