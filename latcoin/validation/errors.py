class ValidationError(Exception):
    pass

class StructuralValidationError(ValidationError):
    pass

class ContextValidationError(ValidationError):
    pass

class WitnessValidationError(ValidationError):
    pass

class BlockValidationError(ValidationError):
    pass
