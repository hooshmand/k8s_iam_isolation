from dataclasses import field, fields, MISSING
from typing import Any, Callable, List, Optional, Union
from InquirerPy import inquirer


def PromptField(prompt_type: str,
               message: str,
               default: Any = MISSING,
               validate: Optional[Callable[[Any], bool]] = None,
               transform: Optional[Callable[[Any], Any]] = None,
               choices: Optional[Union[List[Any], Callable[[], List[Any]]]] = None,
               prompt_args: Optional[dict] = None):
    """
    Helper to create a dataclass field with attached InquirerPy prompt metadata.
    - prompt_type: Name of the InquirerPy prompt (e.g., "text", "confirm", "select").
    - message: The prompt message to display to the user.
    - default: (Optional) Default value for the field (user can override it).
    - validate: (Optional) A function or Validator to validate input (InquirerPy `validate` parameter).
    - transform: (Optional) A function to transform the input (InquirerPy `filter` parameter) before storing.
    - choices: (Optional) List of choices for selection-type prompts (e.g., for "select" or "checkbox").
    - prompt_args: (Optional) Dict of additional keyword args for the prompt (if needed).
    """
    # Prepare metadata dictionary for this field
    meta = {"prompt_type": prompt_type, "message": message}
    if validate is not None:
        meta["validate"] = validate
    if transform is not None:
        meta["transform"] = transform  # will be used as InquirerPy's `filter`
    if choices is not None:
        meta["choices"] = choices
    if prompt_args is not None:
        meta["prompt_args"] = prompt_args
    # Set the default value if provided; otherwise mark the field as required
    if default is MISSING:
        return field(metadata=meta)
    else:
        return field(default=default, metadata=meta)


class PromptData:
    """Base class that adds an interactive prompt method for dataclass fields."""
    @classmethod
    def from_prompt(cls):
        """
        Prompt the user for each field's value and return an instance of the dataclass.
        Uses the metadata in each field to determine prompt type, message, default, etc.
        """
        values = {}
        for field_def in fields(cls):  # iterate over dataclass fields
            meta = field_def.metadata
            if not meta or "prompt_type" not in meta:
                # Skip fields that have no prompt metadata
                continue

            prompt_type = meta["prompt_type"]
            message = meta.get("message", field_def.name)
            # Determine default value (if any)
            default_val = None
            if field_def.default is not MISSING and field_def.default is not None:
                default_val = field_def.default
            # If a default factory is set (callable), call it to get a default value
            if field_def.default_factory is not MISSING:  # default_factory for dataclass
                default_val = field_def.default_factory()

            # Gather prompt parameters
            prompt_kwargs = {}
            # Include any extra prompt arguments specified
            prompt_kwargs.update(meta.get("prompt_args", {}))
            prompt_kwargs["message"] = message
            if default_val is not None:
                prompt_kwargs["default"] = default_val
            if "validate" in meta:
                prompt_kwargs["validate"] = meta["validate"]
            if "transform" in meta:
                # InquirerPy uses 'filter' to transform the result before returning
                prompt_kwargs["filter"] = meta["transform"]
            if "choices" in meta:
                choices = meta["choices"]
                # If choices is a callable, call it to generate the list
                prompt_kwargs["choices"] = choices() if callable(choices) else choices

            # Invoke the appropriate InquirerPy prompt function
            prompt_func = getattr(inquirer, prompt_type)
            result = prompt_func(**prompt_kwargs).execute()  # run the prompt and get user input
            values[field_def.name] = result
        return cls(**values)  # Create an instance of the dataclass with collected values
