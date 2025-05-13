import { useState, useEffect } from "react";
import {
  Card,
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
import "../styles/forms.scss";
import { handleUserConsent } from "../api/userApi";
import URL_PARAMS from "../constants/urlParams";
import Container from "../components/Container";
import FlexContainer from "../components/FlexContainer";

const { Panel } = Collapse;
const { Title, Text, Paragraph } = Typography;

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

export default function ConsentForm() {
  const [loading, setLoading] = useState(false);
  const [clientName, setClientName] = useState("An external application");
  const [scopes, setScopes] = useState(defaultScopes);

  const urlParams = new URLSearchParams(window.location.search);
  const clientID = urlParams.get(URL_PARAMS.CLIENT_ID);
  const redirectURI = urlParams.get(URL_PARAMS.REDIRECT_URI);
  const state = urlParams.get(URL_PARAMS.STATE) || "";
  const scope = urlParams.get(URL_PARAMS.SCOPE) || "";
  const responseType = urlParams.get(URL_PARAMS.RESPONSE_TYPE) || "";
  const nonce = urlParams.get(URL_PARAMS.NONCE) || "";
  const display = urlParams.get(URL_PARAMS.DISPLAY) || "";

  useEffect(() => {
    if (scope) {
      setScopes(scope.split(" "));
    }
  }, [scope]);

  useEffect(() => {
    handleGetConsent();
  }, []);

  const handleGetConsent = async () => {
    try {
      const data = await handleUserConsent({
        clientID: clientID,
        redirectURI: redirectURI,
        scope: scope,
        responseType: responseType,
        state: state,
        nonce: nonce,
        display: display,
        scopes: scopes,
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
  };

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
        information in accordance with their terms of service and privacy
        policy. You can revoke access at any time.
      </Paragraph>

      <Row gutter={16}>
        <Col span={12}>
          <Button
            block
            onClick={() => handleConsent({ approved: false })}
            className="consent-button deny-button"
          >
            Deny
          </Button>
        </Col>
        <Col span={12}>
          <Button
            type="primary"
            block
            loading={loading}
            onClick={() => handleConsent({ approved: true })}
            className="consent-button approve-button"
          >
            Approve
          </Button>
        </Col>
      </Row>
    </FlexContainer>
  );
}
