from typing import Dict, List, Optional, TYPE_CHECKING

from ..utils import SavedSecret
from ..config import Config
from .irresource import IRResource
from .irtlscontext import IRTLSContext

if TYPE_CHECKING:
    from .ir import IR


class IRHost(IRResource):
    AllowedKeys = {
        'acmeProvider',
        'hostname',
        'selector',
        'tlsSecret',
    }

    label_selectors: List[str]

    def __init__(self, ir: 'IR', aconf: Config,
                 rkey: str,      # REQUIRED
                 name: str,      # REQUIRED
                 location: str,  # REQUIRED
                 namespace: Optional[str]=None,
                 kind: str="IRHost",
                 apiVersion: str="ambassador/v2",   # Not a typo! See below.
                 **kwargs) -> None:

        new_args = {
            x: kwargs[x] for x in kwargs.keys()
            if x in IRHost.AllowedKeys
        }

        super().__init__(
            ir=ir, aconf=aconf, rkey=rkey, location=location,
            kind=kind, name=name, namespace=namespace, apiVersion=apiVersion,
            **new_args
        )

    def setup(self, ir: 'IR', aconf: Config) -> bool:
        ir.logger.info(f"Host {self.name} setting up")

        self.label_selectors = []
        self.label_match_string: Optional[str] = None

        sel = self.get('selector') or {}
        self.match_labels = sel.get('matchLabels') or {}

        if self.match_labels:
            for k, v in self.match_labels.items():
                self.label_selectors.append(f"{k}={v}")

            self.label_match_string = ",".join(self.label_selectors)

        tls_ss: Optional[SavedSecret] = None
        pkey_ss: Optional[SavedSecret] = None

        if self.get('tlsSecret', None):
            tls_secret = self.tlsSecret
            tls_name = tls_secret.get('name', None)

            if tls_name:
                ir.logger.info(f"Host {self.name}: TLS secret name is {tls_name}")

                tls_ss = self.resolve(ir, tls_name)

                if tls_ss:
                    # OK, we have a TLS secret! Fire up a TLS context for it, if one doesn't
                    # already exist.

                    ctx_name = f"{self.name}-context"

                    if ir.has_tls_context(ctx_name):
                        ir.logger.info(f"Host {self.name}: TLSContext {ctx_name} already exists")
                    else:
                        ir.logger.info(f"Host {self.name}: creating TLSContext {ctx_name}")

                        # XXX Ew. IRTLSContext should work with kwargs, no??
                        ctx = IRTLSContext(ir, aconf,
                                           rkey=self.rkey,
                                           name=ctx_name,
                                           namespace=self.namespace,
                                           metadata_labels=self.match_labels,
                                           location=self.location,
                                           hosts=[ self.hostname ],
                                           secret=tls_name)

                        if ctx.is_active():
                            ctx.referenced_by(self)
                            ctx.sourced_by(self)

                            ir.save_tls_context(ctx)
                        else:
                            ir.logger.error(f"Host {self.name}: new TLSContext {ctx_name} is not valid")
                else:
                    ir.logger.error(f"Host {self.name}: continuing with invalid TLS secret {tls_name}")
                    return False

        if self.get('acmeProvider', None):
            acme = self.acmeProvider
            pkey_secret = acme.get('privateKeySecret', None)

            if pkey_secret:
                pkey_name = pkey_secret.get('name', None)

                if pkey_name:
                    ir.logger.info(f"Host {self.name}: ACME private key name is {pkey_name}")

                    pkey_ss = self.resolve(ir, pkey_name)

                    if not pkey_ss:
                        ir.logger.error(f"Host {self.name}: continuing with invalid private key secret {pkey_name}")

        return True

    def matches_labels(self, labels: Dict[str, str]) -> bool:
        if not self.match_labels:
            return True

        if not labels:
            return False

        return all([ labels.get(k) == v for k, v in self.match_labels.items() ])

    def  matches(self, resource: IRResource) -> bool:
        if not self.match_labels:
            return True

        return self.matches_labels(resource.metadata_labels)

    def resolve(self, ir: 'IR', secret_name: str) -> SavedSecret:
        # Try to use our namespace for secret resolution. If we somehow have no
        # namespace, fall back to the Ambassador's namespace.
        namespace = self.namespace or ir.ambassador_namespace

        return ir.resolve_secret(self, secret_name, namespace)


class HostFactory:
    @classmethod
    def load_all(cls, ir: 'IR', aconf: Config) -> None:
        assert ir

        hosts = aconf.get_config('hosts')

        if hosts:
            for config in hosts.values():
                ir.logger.debug("creating host for %s" % repr(config.as_dict()))

                host = IRHost(ir, aconf, **config)

                if host.is_active():
                    host.referenced_by(config)
                    host.sourced_by(config)

                    ir.save_host(host)
