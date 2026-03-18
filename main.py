"""
main.py
-------
Entry point — run this file to start the interactive CLI.

    python main.py
"""

from gateway import SecurityGateway


def print_result(result: dict):
    print("\nAnalysis Result:")
    print(f"  Injection Score    : {result['injection_score']}")
    print(f"  PII Detected       : {result['pii_count']}")
    print(f"  Composite Detected : {result['composite_detected']}")
    print(f"  Decision           : {result['decision']}")
    print(f"  Output             : {result['output']}")
    print(f"  Latency            : {result['latency_ms']} ms\n")


if __name__ == "__main__":
    gateway = SecurityGateway()
    print("LLM Security Gateway - Interactive Mode")
    print("Type 'exit' to quit.\n")

    while True:
        user_input = input("Enter text: ")
        if user_input.strip().lower() == "exit":
            print("Exiting...")
            break
        result = gateway.process(user_input)
        print_result(result)
