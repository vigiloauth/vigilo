import React from "react";
import PropTypes from "prop-types";

/**
 * Container
 *
 * A generic container component that applies customizable styles,
 * including width and maxWidth, to its children.
 *
 * @component
 * @example
 * <Container width="80%" maxWidth="500px" style={{ backgroundColor: "#f0f0f0" }}>
 *   <p>Hello World</p>
 * </Container>
 *
 * @param {object} props - The props for the component.
 * @param {React.ReactNode} props.children - The content to render inside the container.
 * @param {string} [props.width="100%"] - CSS width of the container.
 * @param {string} [props.maxWidth="350px"] - CSS maxWidth of the container.
 * @param {object} [props.style={}] - Additional CSS styles to apply.
 *
 * @returns {JSX.Element} The styled container element.
 */
const Container = ({
  children,
  width = "100%",
  maxWidth = "350px",
  maxHeight = "600px",
  style = {},
  layout = "vertical",
  className,
}) => {
  return (
    <div
      className={className}
      style={{
        width,
        layout,
        maxWidth,
        maxHeight,
        ...style,
      }}
    >
      {children}
    </div>
  );
};

Container.propTypes = {
  children: PropTypes.node.isRequired,
  width: PropTypes.string,
  maxWidth: PropTypes.string,
  style: PropTypes.object,
  layout: PropTypes.string,
  className: PropTypes.string,
};

export default Container;
