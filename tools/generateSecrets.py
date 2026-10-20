# @             Project: BuaaSignIn -> generateSecrets.py
# @              Author: WangNan
# @       Creation Date: 2026/9/5 16:37
# @         Description: Generate an random secret
# @ Version Information: Created by WangNan, 2026/6/3
# ===================================================================================

import secrets

print(secrets.token_hex(32))