import React, { useState } from "react";
import {
  Form,
  Button,
  Checkbox,
  Card,
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
import FlexContainer from "../components/FlexContainer";
import Container from "../components/Container";
import FormInput from "../components/FormInput";
import { authenticateUser } from "../api/userApi";
import "../styles/AuthenticationForm.scss";

const { Title, Text, Link } = Typography;

export default function AuthenticationForm() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const urlParams = new URLSearchParams(window.location.search);
  const clientId = urlParams.get("client_id");
  const redirectUri = urlParams.get("redirect_uri");
  const state = urlParams.get("state") || "";
  const scope = urlParams.get("scope") || "";
  const responseType = urlParams.get("response_type") || "";
  const nonce = urlParams.get("nonce") || "";
  const display = urlParams.get("display") || "";

  const onFinish = async () => {
    setLoading(true);
    try {
      const data = await authenticateUser({
        username,
        password,
        clientId,
        redirectUri,
        state,
        scope,
        responseType,
        nonce,
        display,
      });

      console.log(data);
      if (data.oauth_redirect_url) {
        message.success("Login successful. You are being redirected");
        setTimeout(() => {
          window.location.replace(data.oauth_redirect_url);
        }, 2000);
      }
    } catch (err) {
      message.error(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <FlexContainer className="auth-container">
      <Card className="auth-card" variant="borderless">
        <Container className="auth-header">
          <Title>Welcome Back</Title>
          <Text className="subtitle" type="secondary">
            Please sign in to continue
          </Text>
        </Container>

        <Form
          className="auth-form"
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

          <Form.Item className="auth-form">
            <Button
              type="primary"
              className="auth-button"
              htmlType="submit"
              block
              loading={loading}
            >
              Sign In
            </Button>
          </Form.Item>

          <Divider plain className="auth-divider">
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

          <Container className="auth-footer">
            <Text type="secondary">
              Don't have an account? <Link>Sign up</Link>
            </Text>
          </Container>
        </Form>
      </Card>
    </FlexContainer>
  );
}
