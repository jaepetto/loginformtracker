import attr


@attr.s
class CheckedUrl:
    url = attr.ib(default='', validator=attr.validators.instance_of(str))
    landing_url = attr.ib(default='', validator=attr.validators.instance_of(str))
    flagged_as_unsafe = attr.ib(default=False, validator=attr.validators.instance_of(bool))
    messages = attr.ib(default=[], validator=attr.validators.instance_of(list))
    external_links = attr.ib(default=[], validator=attr.validators.instance_of(list))

