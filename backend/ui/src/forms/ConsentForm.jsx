import { useState, useEffect, useCallback } from "react";
import {
  Typography,
  Button,
  message,
  Space,
  Alert,
  Avatar,
  Row,
  Col,
  Collapse,
} from "antd";
import {
  UserOutlined,
  MailOutlined,
  PhoneOutlined,
  HomeOutlined,
  ClockCircleOutlined,
  IdcardOutlined,
} from "@ant-design/icons";
import { handleUserConsent } from "../api/userApi";
import { useApplicationContext } from "../context/ApplicationContext";
import Container from "../components/Container";
import FlexContainer from "../components/FlexContainer";
import "../styles/forms.scss";

const { Panel } = Collapse;
const { Title, Text, Paragraph, Link } = Typography;

const scopeDetails = {
  openid: {
    title: "Verify your identity",
    description:
      "This allows the application to authenticate who you are securely. This permission is required to use the service and ensures your account can be verified.",
    icon: <IdcardOutlined />,
    required: true,
  },
  profile: {
    title: "Profile Information",
    description:
      "This grants access to your basic profile details including your name, preferred language, and profile picture. No sensitive personal data will be shared.",
    icon: <UserOutlined />,
    required: false,
  },
  email: {
    title: "Email Address",
    description:
      "This allows the application to view your email address and whether it has been verified. The app may use this to send you important notifications and updates.",
    icon: <MailOutlined />,
    required: false,
  },
  phone: {
    title: "Phone Number",
    description:
      "This provides access to your phone number and its verification status. The app may use this for account recovery or sending security codes for two-factor authentication.",
    icon: <PhoneOutlined />,
    required: false,
  },
  address: {
    title: "Address Information",
    description:
      "This grants access to your physical address details. The application may use this information for shipping, location-based services, or to personalize your experience.",
    icon: <HomeOutlined />,
    required: false,
  },
  offline_access: {
    title: "Offline Access",
    description:
      "This allows the application to access your authorized information even when you're not actively using it. Your permissions remain valid until you explicitly revoke them.",
    icon: <ClockCircleOutlined />,
    required: false,
  },
};

const defaultScopes = ["profile", "openid", "address", "email"];

export default function ConsentForm({ policyURI }) {
  const [loading, setLoading] = useState(false);
  const [clientName, setClientName] = useState("An external application");
  const [scopes, setScopes] = useState(defaultScopes);
  const {
    clientID,
    redirectURI,
    scope,
    responseType,
    state,
    nonce,
    display,
    acrValues,
    claims,
  } = useApplicationContext();

  const handleGetConsent = useCallback(async () => {
    try {
      const data = await handleUserConsent({
        clientID,
        redirectURI,
        scope,
        responseType,
        state,
        nonce,
        display,
        scopes,
        acrValues,
        claims,
        method: "GET",
      });

      if (data.approved && data.approved === true) {
        window.location.href = data.redirect_uri;
      } else {
        setClientName(data.client_name);
      }
    } catch (err) {
      message.error("Something went wrong. Please try again later");
    }
  }, [
    clientID,
    redirectURI,
    scope,
    responseType,
    state,
    nonce,
    display,
    scopes,
  ]);

  useEffect(() => {
    if (scope) {
      setScopes(scope.split(" "));
    }
  }, [scope]);

  useEffect(() => {
    handleGetConsent();
  }, [handleGetConsent]);

  const handleConsent = async ({ approved }) => {
    try {
      setLoading(true);
      const data = await handleUserConsent({
        clientID,
        redirectURI,
        scope,
        responseType,
        state,
        nonce,
        display,
        approved: approved,
        scopes,
        acrValues,
        claims,
      });

      if (data.redirect_uri) {
        message.success(
          "Your consent has been recorded. You are being redirected",
        );
        setTimeout(() => {
          window.location.href = data.redirect_uri;
        }, 1000);
      }
    } catch (err) {
      message.error("Something went wrong. Please try again later");
    } finally {
      setLoading(false);
    }
  };

  // Sort scopes to ensure openid (required scope) always appears first
  const sortedScopes = [...scopes].sort((a, b) => {
    if (a === "openid") return -1;
    if (b === "openid") return 1;
    return 0;
  });

  return (
    <FlexContainer vertical={true} height="100%">
      <Container className="title-container">
        <Title className="card-title">
          {clientName} would like to access your account
        </Title>
      </Container>
      <Alert
        description="Review the details below"
        type="info"
        showIcon
        className="info-alert"
      />
      <Collapse
        accordion
        bordered={false}
        expandIconPosition="end"
        className="scope-collapse"
      >
        {sortedScopes.map((scope) => {
          const { title, description, icon, required } = scopeDetails[scope];
          return (
            <Panel
              key={scope}
              header={
                <Space>
                  <Avatar icon={icon} className="scope-avatar" size="small" />
                  <Text strong>{title}</Text>
                  {required && (
                    <Text type="secondary" className="required-label">
                      (Required)
                    </Text>
                  )}
                </Space>
              }
            >
              <Paragraph className="scope-description">{description}</Paragraph>
            </Panel>
          );
        })}
      </Collapse>
      <Paragraph className="consent-disclaimer">
        By approving, you allow{" "}
        {clientName ? "an external application" : clientName} to use your
        information in accordance with their terms of service and{" "}
        {policyURI === "" ? (
          "privacy policy. "
        ) : (
          <Link target="_blank" className="secondary-link" href={policyURI}>
            privacy policy.{" "}
          </Link>
        )}
        You can revoke access at any time.
      </Paragraph>

      <Container width="100%">
        <Row gutter={24}>
          <Col xs={24} sm={12}>
            <Button
              block
              onClick={() => handleConsent({ approved: false })}
              className="consent-button deny-button"
            >
              Deny
            </Button>
          </Col>
          <Col xs={24} sm={12}>
            <Button
              type="primary"
              block
              loading={loading}
              disabled={loading}
              onClick={() => handleConsent({ approved: true })}
              className="consent-button approve-button"
            >
              Approve
            </Button>
          </Col>
        </Row>
      </Container>
    </FlexContainer>
  );
}
