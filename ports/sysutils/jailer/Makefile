PORTNAME=	jailer
DISTVERSIONPREFIX=	v
DISTVERSION=	0.5.1
CATEGORIES=	sysutils

MAINTAINER=	grepjava@gmail.com
COMMENT=	Build, run and publish OCI images of FreeBSD jails
WWW=		https://github.com/grepjava/jailer

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

ONLY_FOR_ARCHS=	aarch64 amd64
ONLY_FOR_ARCHS_REASON=	tested on these only

LIB_DEPENDS=	libzstd.so:archivers/zstd

USES=		cargo
USE_GITHUB=	yes
GH_ACCOUNT=	grepjava

PLIST_FILES=	bin/jailer \
		share/man/man1/jailer.1.gz

.include "${.CURDIR}/Makefile.crates"
.include <bsd.port.pre.mk>

.if ${OSVERSION} < 1500000
IGNORE=		needs FreeBSD 15 or newer
.endif

post-install:
	${STRIP_CMD} ${STAGEDIR}${PREFIX}/bin/jailer
	${INSTALL_MAN} ${WRKSRC}/man/jailer.1 ${STAGEDIR}${PREFIX}/share/man/man1

.include <bsd.port.post.mk>
