#ifndef ZT_SIGN_ED25519_H
#define ZT_SIGN_ED25519_H

int zt_ed25519_keygen(const char *priv_path, const char *pub_path);
int zt_ed25519_sign_file(const char *file, const char *priv_key);
int zt_ed25519_verify_file(const char *file, const char *pub_key);

#endif
