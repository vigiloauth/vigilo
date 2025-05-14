import { useState } from "react";
import Container from "../components/Container";
import FormInput from "../components/FormInput";
import { authenticateUser } from "../api/userApi";
import { useApplicationContext } from "../context/ApplicationContext";
import {
  Form,
  Button,
  Checkbox,
  Typography,
  Row,
  Col,
  Divider,
  message,
} from "antd";
import {
  UserOutlined,
  LockOutlined,
  GoogleOutlined,
  FacebookOutlined,
} from "@ant-design/icons";
import "../styles/forms.scss";

const { Text, Link } = Typography;

const AuthenticationForm = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const { clientID, redirectURI, state, scope, responseType, nonce, display } =
    useApplicationContext();

  const onFinish = async () => {
    setLoading(true);
    try {
      const data = await authenticateUser({
        username,
        password,
        clientID,
        redirectURI,
        state,
        scope,
        responseType,
        nonce,
        display,
      });

      console.log(data.oauth_redirect_url);
      if (data.oauth_redirect_url) {
        message.success("Login successful. You are being redirected");
        setTimeout(() => {
          window.location.replace(data.oauth_redirect_url);
        }, 1000);
      }
    } catch (err) {
      message.error(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Form
      className="form"
      name="login"
      initialValues={{ remember: false }}
      onFinish={onFinish}
      layout="vertical"
    >
      <FormInput
        placeholder="Username"
        name="username"
        required={true}
        message=""
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        icon={<UserOutlined className="site-form-item-icon" />}
      />

      <FormInput
        placeholder="Password"
        name="password"
        required={true}
        message=""
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        isPassword={true}
        icon={<LockOutlined className="site-form-item-icon" />}
      />

      <Form.Item>
        <Row justify="space-between" align="middle">
          <Col>
            <Form.Item name="remember" valuePropName="checked" noStyle>
              <Checkbox>Remember me</Checkbox>
            </Form.Item>
          </Col>
          <Col>
            <Link>Forgot password?</Link>
          </Col>
        </Row>
      </Form.Item>

      <Form.Item className="form">
        <Button
          type="primary"
          className="button"
          htmlType="submit"
          block
          loading={loading}
        >
          Sign In
        </Button>
      </Form.Item>

      <Divider plain className="divider">
        or continue with
      </Divider>

      <Form.Item className="social-buttons">
        <Row gutter={[16, 16]}>
          <Col xs={24} sm={12}>
            <Button icon={<GoogleOutlined />} block>
              Google
            </Button>
          </Col>
          <Col xs={24} sm={12}>
            <Button icon={<FacebookOutlined />} block>
              Facebook
            </Button>
          </Col>
        </Row>
      </Form.Item>

      <Container className="footer">
        <Text type="secondary">
          Don't have an account? <Link>Sign up</Link>
        </Text>
      </Container>
    </Form>
  );
};

export default AuthenticationForm;
