import { Form, Input } from "antd";
import React from "react";
import PropTypes from "prop-types";

/**
 * A reusable form input component that supports both text and password inputs.
 *
 * @component
 * @param {Object} props - The props object.
 * @param {string} props.label - The label for the form input.
 * @param {string} props.name - The name of the form field (used for form data binding).
 * @param {boolean} props.required - Whether the field is required.
 * @param {string} props.message - Validation message shown when the field is invalid.
 * @param {string} props.value - The current value of the input.
 * @param {function} props.onChange - Callback function triggered when the input value changes.
 * @param {React.ReactNode} props.icon - Optional icon to display in the input prefix.
 * @param {boolean} [props.isPassword=false] - If true, renders a password input field.
 *
 * @returns {JSX.Element} A Form.Item with an Input or Password Input inside.
 */
const FormInput = ({
  label,
  placeholder,
  name,
  required,
  message,
  value,
  onChange,
  icon,
  isPassword = false,
  validateStatus = "",
  size = "middle",
  style = {},
  className,
  ...props
}) => {
  const InputComponent = isPassword ? Input.Password : Input;
  return (
    <Form.Item
      label={label}
      name={name}
      style={style}
      rules={[{ required, message }]}
      className={className}
    >
      <InputComponent
        prefix={icon}
        value={value}
        size={size}
        placeholder={placeholder}
        onChange={onChange}
        status={validateStatus === "error" ? "error" : ""}
        {...props}
      />
    </Form.Item>
  );
};

FormInput.propTypes = {
  label: PropTypes.string,
  name: PropTypes.string.isRequired,
  required: PropTypes.bool,
  message: PropTypes.string,
  value: PropTypes.string,
  onChange: PropTypes.func,
  icon: PropTypes.node,
  isPassword: PropTypes.bool,
  validateStatus: PropTypes.string,
  placeholder: PropTypes.string,
  size: PropTypes.oneOf(["large", "middle", "small"]),
  className: PropTypes.string,
};

export default FormInput;
