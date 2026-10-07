from . import nikto, nmap, nuclei, zap

# Order here is the order the Planner sees the tools in.
TOOLS = {module.SPEC["name"]: module for module in (nmap, zap, nuclei, nikto)}
