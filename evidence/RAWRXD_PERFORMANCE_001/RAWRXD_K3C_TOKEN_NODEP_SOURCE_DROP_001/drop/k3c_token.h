/* k3c_token.h — no-dep TOKEN <-> K3-C contract. */
#ifndef RAWRXD_K3C_TOKEN_H
#define RAWRXD_K3C_TOKEN_H

#ifdef __cplusplus
extern "C" {
#endif

unsigned k3c_token(unsigned token, void *state); /* TOKEN <-> K3-C */

#define K3C(token) k3c_token((token), (k3c_state))

#ifdef __cplusplus
}
#endif

#endif /* RAWRXD_K3C_TOKEN_H */
