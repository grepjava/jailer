PORTNAME=	jailer
DISTVERSIONPREFIX=	v
DISTVERSION=	0.1.0
CATEGORIES=	sysutils

MAINTAINER=	grepjava@gmail.com
COMMENT=	Build, run and publish OCI images of FreeBSD jails
WWW=		https://github.com/grepjava/jailer

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

USES=		cargo
USE_GITHUB=	yes
GH_ACCOUNT=	grepjava

PLIST_FILES=	bin/jailer \
		share/man/man1/jailer.1.gz

post-install:
	${STRIP_CMD} ${STAGEDIR}${PREFIX}/bin/jailer
	${INSTALL_MAN} ${WRKSRC}/man/jailer.1 ${STAGEDIR}${PREFIX}/share/man/man1

.include "${.CURDIR}/Makefile.crates"
.include <bsd.port.mk>
