def client_ports(n: int) -> tuple[int, int]:
    http = 8800 + (n - 1) * 10 + 3
    return http, http + 1
