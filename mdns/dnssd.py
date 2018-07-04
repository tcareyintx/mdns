from itertools import product
import logging
import re
import string
import unicodedata


LOG = logging.getLogger(__file__)

INSTANCE_REGEX_PATTERN = re.compile(b'^.*[^' + b''.join(chr(c).encode('utf-8') for c in range(0x00, 0x1F)) + chr(0x7F).encode('utf-8') + b'].*$')
SERVICE_NAME_REGEX_PATTERN = re.compile(b'^([0-9]+(\-){0,1})*[A-Za-z]((\-){0,1}[A-Za-z0-9])*$')


class Error(Exception):
    pass


class InvalidServiceInstanceNamePortionError(Error):
    pass


class InvalidInstanceError(InvalidServiceInstanceNamePortionError):
    pass


class InvalidServiceError(InvalidServiceInstanceNamePortionError):
    pass


class InvalidSubtypeError(InvalidServiceInstanceNamePortionError):
    pass


def instance_to_bytes(instance, escape=True):
    """
    Encode unicode string into bytes by taking into account all restrictions set on the <Instance> portion.

    - MUST NOT contain ASCII control characters: 0x00...0x1F + 0x7F
    - MUST NOT exceed 63 octets in length
    - SHOULD escape all dots with '\' and therefore each '\'.

    @attention: Escaping may increase length of the string and otherwise good string may exceed 63 octets limitation.
    @see: RFC 6763, sections 4.1.1. and 4.3.

    @param instance: The <Instance> portion of a Service Instance Name.
    @type instance: unicode

    @param escape: Escape all dots and backslashes by prepending backslash to each char.
    @type escape: bool

    @return: Bytes that represent the <Instance> portion.
    @rtype: bytes
    """
    instance = unicodedata.normalize('NFC', instance).encode('utf-8')

    if not re.match(INSTANCE_REGEX_PATTERN, instance):
        raise InvalidInstanceError("instance MUST follow rules defined in RFC 6763, 4.1.1.")

    if escape:
        instance = instance.replace(b'\\', b'\\\\')
        instance = instance.replace(b'.', b'\\.')

    if len(instance) > 63:
        raise InvalidInstanceError("as per RFC 6763, instance name MUST be up to 63 octets in length")

    return instance


def service_to_bytes(service):
    """
    Encode unicode string into bytes by taking into account all restrictions set on the <Service> portion.

    - MUST consist of 2 DNS labels
    - The first label MUST start with _ and MUST have length in range from 1 to 15 octets (excluding leading underscore)
    - The first label MUST follow rules defined in RFC 6335, 5.1.
    - The second label MUST be either '_tcp' or '_udp'

    @see: RFC 6335, 5.1.
    @see: RFC 6763, 4.1.2. and 4.7.

    @param service: The <Service> portion of a Service Instance Name.
    @type service: unicode

    @return: Bytes that represent the <Service> portion.
    @rtype: bytes
    """
    service = service.encode('ascii')
    name, sep, proto = service.rpartition(b'.')

    if not name:
        raise InvalidServiceError("as per RFC 6763 service MUST consist of 2 labels: service name and protocol")

    if proto != b'_tcp' and proto != b'_udp':
        raise InvalidServiceError("as per RFC 6763, second label of the service MUST be either '_tcp' or '_udp'")

    if not name.startswith(b'_'):
        raise InvalidServiceError("as per RFC 6763, service name MUST start with and underscore '_'")

    name = name[1:]

    if not 0 < len(name) < 16:
        raise InvalidServiceError("as per RFC 6335, service name MUST at least 1 octet and at most 15 octets in length (not counting the mandatory underscore)")

    if not re.match(SERVICE_NAME_REGEX_PATTERN, name):
        raise InvalidServiceError("service name MUST follow rules defined in RFC 6335, 5.1.")

    return service


def subtype_to_bytes(subtype):
    """
    Encode unicode string into bytes by taking into account all restrictions set on subtype of the <Service> portion.

    - MUST NOT exceed 63 octets in length

    @param subtype: Subtype of the <Service> portion.
    @type subtype: unicode

    @return: Bytes that represent subtype of the <Service> portion.
    @rtype: bytes
    """
    if len(subtype) > 63:
        raise InvalidSubtypeError("as per RFC 6763, subtypes MUST be up to 63 octets in length")

    return subtype.encode('utf-8')


def domain_to_bytes(domain):
    """
    Encode unicode string into bytes by taking into account all restrictions set on the <Domain> portion and
    recommendations to partially convert domain into punycode.

    @see: RFC 6763, 4.1.3.

    @param domain: The <Domain> portion of a Service Instance Name.
    @type domain: unicode

    @return: List of all variations of the domain from completely UTF-8 encoded to completely Punycode encoded string.
    @rtype: list
    """
    domain = unicodedata.normalize('NFC', domain)
    domain = domain.rstrip('.')
    labels = domain.split('.')
    utf8_labels = [l.encode('utf-8') for l in labels]
    idna_labels = [l.encode('idna') for l in labels]
    options = []

    for i in product(*zip(utf8_labels, idna_labels)):
        opt = b'.'.join(i)
        if not opt in options:
            options.append(opt)

    return options


class ServiceInstance(object):
    def __init__(self, instance, service, domain, subtype=None):
        """

        @param instance: <Instance> portion of a Service Instance Name. E.g. b'Service\032Discovery'
        @type instance: bytes

        @param service: <Service> portion of a Service Instance Name. E.g. b'_http._tcp'
        @type service: bytes

        @param domain: <Domain> portion of a Service Instance Name. E.g. b'Building 2, 4th Floor.example.com'
        @type domain: bytes

        @param subtype: Optional subtype of the <Service> portion of a Service Instance Name. E.g. b'_printer'
        @type subtype: bytes

        @see ServiceInstance.instance_to_bytes
        @see ServiceInstance.service_to_bytes
        @see ServiceInstance.domain_to_bytes
        """
        self._instance = instance
        self._service = service
        self._domain = domain
        self._subtype = subtype

        if self.service_instance_name > 256:
            LOG.warning("")

    @property
    def instance(self):
        return self._instance

    @property
    def service(self):
        return self._service

    @property
    def subtype(self):
        return self._subtype

    @property
    def service_name(self):
        return self.service.split(b'.')[0][1:]

    @property
    def domain(self):
        return self._domain

    @property
    def service_instance_name(self):
        return b'.'.join([self.instance, self.service, self.domain]) + b'.'

    def is_instance_of_service(self, service, subtype=None):
        """
        Determines if current object is an instance of service.

        @attention: The comparison is performed case-insensitively (meaning ASCII letters).
        @note: subtype is only taken into account when passed.
        @see: RFC 6763, 7. and 7.1.

        @param service: <Service> portion of a Service Instance Name.
        @type service: bytes

        @param subtype: Optional subtype.
        @type subtype: bytes

        @return: True if current object is instance of service with subtype. False otherwise.
        """
        if subtype is not None and self.subtype is None:
            return False

        service = service.translate(string.ascii_uppercase, string.ascii_lowercase)
        self_service = self.service.translate(string.ascii_uppercase, string.ascii_lowercase)

        if service == self_service:
            if subtype is not None:
                subtype = subtype.translate(string.ascii_uppercase, string.ascii_lowercase)
                self_subtype = subtype.translate(string.ascii_uppercase, string.ascii_lowercase)
                return subtype == self_subtype
            else:
                return True
        else:
            return False
