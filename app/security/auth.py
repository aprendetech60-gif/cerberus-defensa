async def get_real_ip(request: Request) -> str:
    """Devuelve la IP resuelta por el middleware de seguridad."""
    return getattr(request.state, "real_ip", "unknown")