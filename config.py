import json

MANDATORY_FIELDS = ["port", "timeout"]
OPTIONAL_FIELDS = ["function_code", "sub_function_code"]

class InvalidConfiguration(Exception):
    pass
class MissingConfigField(Exception):
    pass
class ModbusConfig(object):
    def __init__(self, conf_path):
        with open(conf_path, "rb") as config_file:
            self.config = json.load(config_file)
	self.validate_config()
    
    def __getattr__(self, name):
        try:
            return self.config[name]
        except KeyError:
            raise MissingConfigField("{} is missing from the configuration".format(name))
    def validate_config(self):
        missing_fields = []
        for f in MANDATORY_FIELDS:
            if not self.config.has_key(f):
                missing_fields.append(f)
        if missing_fields:
            raise InvalidConfiguration("Missing fields in the configuration: {}".format(",".join(missing_foelds)))

