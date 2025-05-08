import { Form, Button } from "antd";
import React from "react";
import PropTypes from "prop-types";

const BaseButton = ({
  type = "primary",
  onClick,
  loading,
  children,
  style = {},
  block = true,
  disabled = false,
  size = "default",
}) => {
  return (
    <Form.Item>
      <Button
        size={size}
        style={style}
        type={type}
        onClick={onClick}
        loading={loading}
        block={block}
        disabled={disabled}
      >
        {children}
      </Button>
    </Form.Item>
  );
};

BaseButton.propTypes = {
  type: PropTypes.oneOf(["primary", "link", "text", "default", "dashed"]),
  onClick: PropTypes.func,
  loading: PropTypes.bool,
  children: PropTypes.node.isRequired,
  style: PropTypes.object,
  block: PropTypes.bool,
  disabled: PropTypes.bool,
  size: PropTypes.oneOf(["large", "default", "small"]),
};

export default BaseButton;
