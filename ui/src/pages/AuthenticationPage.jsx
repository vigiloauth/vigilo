import { useState, useEffect } from "react";
import { Card, Typography, Spin } from "antd";
import FlexContainer from "../components/FlexContainer";
import Container from "../components/Container";
import AuthenticationForm from "../forms/AuthenticationForm";
import AuthenticationPopup from "../popups/AuthenticationPopup";
import { useApplicationContext } from "../context/ApplicationContext";
import "../styles/AuthenticationPage.scss";

const { Title, Text } = Typography;

export default function AuthenticationPage({ display }) {
  const [clientLogo, setClientLogo] = useState(null);
  const [clientName, setClientName] = useState("");
  const [imageLoaded, setImageLoaded] = useState(false);
  const { clientInfo, loading: contextLoading } = useApplicationContext();

  const defaultSignInMessage = "Please sign in to continue";
  const signInMessage = `You are signing into ${clientName}`;

  useEffect(() => {
    if (!clientInfo) return;
    setClientName(clientInfo.name || "");

    const img = new Image();
    img.src = clientInfo.logo_uri;
    img.onload = () => {
      setClientLogo(<img src={clientInfo.logo_uri} alt="client logo" />);
      setImageLoaded(true);
    };
    img.onerror = () => {
      setClientLogo(null);
      setImageLoaded(true);
    };
  }, [clientInfo]);

  const isLoading = contextLoading || (clientInfo?.logo_uri && !imageLoaded);

  if (isLoading) {
    return (
      <FlexContainer className="auth-container">
        <Spin size="large" tip="Loading..." />
      </FlexContainer>
    );
  }

  return display === "popup" ? (
    <AuthenticationPopup clientLogo={clientLogo} clientName={clientName} />
  ) : (
    <FlexContainer className="auth-container">
      <Card className="auth-card" variant="borderless">
        <Container className="auth-header">
          {clientLogo ? clientLogo : <Title>Welcome Back</Title>}
          <Text className="subtitle" type="secondary">
            {clientName ? signInMessage : defaultSignInMessage}
          </Text>
        </Container>
        <AuthenticationForm policyURI={clientInfo.policy_uri} />
      </Card>
    </FlexContainer>
  );
}
