import React, { useEffect, useState } from "react";
import { Layout, Typography, Button, Divider, Space } from "antd";
import { ExclamationCircleFilled } from "@ant-design/icons";
import "../styles/ErrorPage.scss";

const { Header, Content } = Layout;
const { Title, Paragraph, Text, Link } = Typography;

const InvalidRedirectErrorPage = () => {
  const [errorType, setErrorType] = useState("");
  const [displayErrorCode, setDisplayErrorCode] = useState("");
  const [displayErrorMessage, setDisplayErrorMessage] = useState(
    "We encountered an issue. Please try again or contact support if the problem persists.",
  );

  const invalidRedirectUriMessageTemplate =
    "The redirect URI '{uri}' specified in the request does not match the redirect URIs configured for the application.";

  const genericTroubleSigningYouInMessage =
    "Sorry, but we're having trouble signing you in.";

  const invalidRedirectUriSolutionSuggestion =
    "Make sure the redirect URI sent in the request matches one added to your application in the VigiloAuth portal.";
  const learnMoreLinkAAD = "";

  useEffect(() => {
    const queryParams = new URLSearchParams(window.location.search);
    const typeFromQuery = queryParams.get("type");
    const uriFromQuery = queryParams.get("uri");

    setErrorType(typeFromQuery);
    setDisplayErrorCode(typeFromQuery);

    if (uriFromQuery) {
      setDisplayErrorMessage(
        invalidRedirectUriMessageTemplate.replace("{uri}", uriFromQuery),
      );
    } else {
      setDisplayErrorMessage(
        invalidRedirectUriMessageTemplate.replace(
          "{uri}",
          "[specific URI not provided in the request]",
        ),
      );
    }
  }, []);

  const handleGoBack = () => {
    console.log("Go back clicked");
    if (window.history.length > 1) {
      window.history.back();
    }
  };

  const handleTryAgain = () => {
    console.log("Try again clicked");
  };

  const currentSolutionSuggestion = invalidRedirectUriSolutionSuggestion;

  return (
    <Layout className="error-layout">
      <Header className="error-header">
        <Title level={1} className="logo">
          VigiloAuth
        </Title>
      </Header>

      <Content className="error-content">
        <div className="error-container">
          <Title level={1} className="error-main-title">
            Sign in
          </Title>
          <div className="error-message-box">
            <ExclamationCircleFilled className="error-icon" />
            <div className="error-text-content">
              <Title level={4} className="error-subtitle">
                {genericTroubleSigningYouInMessage}
              </Title>
              <Paragraph className="error-details-code">
                <Text strong>{displayErrorCode}:</Text> {displayErrorMessage}
              </Paragraph>
              <Paragraph className="error-details-solution">
                {currentSolutionSuggestion}
                {errorType === "invalid_redirect_uri" && (
                  <>
                    {" "}
                    Navigate to{" "}
                    <Link
                      href={learnMoreLinkAAD}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {learnMoreLinkAAD}
                    </Link>{" "}
                    to learn more about how to fix this.
                  </>
                )}
              </Paragraph>
            </div>
          </div>

          <Divider className="error-divider" />

          <Paragraph className="error-additional-info">
            If you're an admin and this issue relates to application
            configuration (like a redirect URI mismatch), please verify the
            settings in your identity provider portal. For other issues, or if
            the problem persists, please contact support or try again later.
          </Paragraph>

          <Space className="error-actions" size="middle">
            <Button
              className="button"
              type="default"
              size="large"
              onClick={handleGoBack}
            >
              Go Back
            </Button>
            <Button
              className="button"
              type="primary"
              size="large"
              onClick={handleTryAgain}
            >
              Try Again
            </Button>
          </Space>

          <div className="error-footer-links">
            <Link href="#" target="_blank" rel="noopener noreferrer">
              Terms of use
            </Link>
            <Link href="#" target="_blank" rel="noopener noreferrer">
              Privacy & cookies
            </Link>
            <Text className="more-options-trigger">...</Text>
          </div>
        </div>
      </Content>
    </Layout>
  );
};

export default InvalidRedirectErrorPage;
