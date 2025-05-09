import React, { useState, useEffect } from "react";
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
import "../styles/ConsentForm.scss";
import { postConsent } from "../api/userApi";
import URL_PARAMS from "../constants/urlParams";

const { Panel } = Collapse;
const { Title, Text, Paragraph } = Typography;

const scopeDetails = {
  openid: {
    title: "Verify your identity",
    description: "Allow this application to verify your identity",
    icon: <IdcardOutlined />,
    required: true,
  },
  profile: {
    title: "Profile Information",
    description: "Access to your profile information",
    icon: <UserOutlined />,
    required: false,
  },
  email: {
    title: "Email Address",
    description: "Access to your email address and verification status",
    icon: <MailOutlined />,
    required: false,
  },
  phone: {
    title: "Phone Number",
    description: "Access to your phone number and verification status",
    icon: <PhoneOutlined />,
    required: false,
  },
  address: {
    title: "Address Information",
    description: "Access to your address information",
    icon: <HomeOutlined />,
    required: false,
  },
  offline_access: {
    title: "Offline Access",
    description: "Access to your information while offline",
    icon: <ClockCircleOutlined />,
    required: false,
  },
};

export default function ConsentForm() {
  const [isMobile, setIsMobile] = useState(false);
  const [loading, setLoading] = useState(false);
  const [clientName, setClientName] = useState("[App]");
  const [scopes, setScopes] = useState([]);

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
  }, [scopes]);

  // Check if screen size is mobile
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768);
    };

    checkMobile();
    window.addEventListener("resize", checkMobile);

    return () => {
      window.removeEventListener("resize", checkMobile);
    };
  }, []);

  const handleApprove = async () => {
    try {
      setLoading(true);
      const data = await postConsent({
        clientID,
        redirectURI,
        scope,
        responseType,
        state,
        nonce,
        display,
        approved: true,
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

  const handleDeny = async () => {
    try {
      setLoading(true);
      const data = await postConsent({
        clientID,
        redirectURI,
        scope,
        responseType,
        state,
        nonce,
        display,
        approved: false,
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

  const renderScopeList = () => {
    return (
      <Collapse
        accordion
        bordered={false}
        expandIconPosition="end"
        style={{
          marginBottom: "15px",
          backgroundColor: "white",
        }}
      >
        {scopes.map((scope) => {
          const { title, description, icon, required } = scopeDetails[scope];
          return (
            <Panel
              key={scope}
              header={
                <Space>
                  <Avatar
                    icon={icon}
                    style={{
                      backgroundColor: "#1890ff",
                      color: "white",
                    }}
                    size="small"
                  />
                  <Text strong>{title}</Text>
                  {required && (
                    <Text type="secondary" style={{ fontSize: "12px" }}>
                      (Required)
                    </Text>
                  )}
                </Space>
              }
            >
              <Paragraph style={{ marginBottom: 5 }}>{description}</Paragraph>
            </Panel>
          );
        })}
      </Collapse>
    );
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        backgroundColor: "#f5f5f5",
        padding: isMobile ? "0" : "40px 16px",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <Card
        variant="borderless"
        style={{
          boxShadow: isMobile ? "none" : "0 4px 12px rgba(0, 0, 0, 0.08)",
          borderRadius: isMobile ? "0" : "8px",
          width: "100%",
          maxWidth: isMobile ? "100%" : "550px",
          minHeight: isMobile ? "100vh" : "auto",
          margin: isMobile ? "0" : "auto",
          padding: isMobile ? "24px 16px" : "32px",
          height: isMobile ? "100vh" : "auto",
          display: "flex",
          flexDirection: "column",
          justifyContent: isMobile ? "center" : "flex-start",
        }}
      >
        <div style={{ textAlign: "center", marginBottom: "24px" }}>
          <Title level={isMobile ? 3 : 2}>
            {clientName} would like to access your account
          </Title>
        </div>

        <Alert
          description="Review the details below"
          type="info"
          showIcon
          style={{ marginBottom: "16px" }}
        />

        {renderScopeList()}

        <Paragraph
          type="secondary"
          style={{ fontSize: "12px", marginBottom: "24px" }}
        >
          By approving, you allow {clientName} to use your information in
          accordance with their terms of service and privacy policy. You can
          revoke access at any time.
        </Paragraph>

        <Row gutter={16}>
          <Col span={12}>
            <Button
              block
              onClick={handleDeny}
              style={{ height: isMobile ? "40px" : "48px" }}
            >
              Deny
            </Button>
          </Col>
          <Col span={12}>
            <Button
              type="primary"
              block
              onClick={handleApprove}
              loading={loading}
              style={{ height: isMobile ? "40px" : "48px" }}
            >
              Approve
            </Button>
          </Col>
        </Row>
      </Card>
    </div>
  );
}
