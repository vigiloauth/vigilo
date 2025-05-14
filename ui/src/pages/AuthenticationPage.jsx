import { useState, useEffect } from "react";
import { Card, Typography } from "antd";
import FlexContainer from "../components/FlexContainer";
import Container from "../components/Container";
import AuthenticationForm from "../forms/AuthenticationForm";
import AuthenticationPopup from "../popups/AuthenticationPopup";
import { useApplicationContext } from "../context/ApplicationContext";
import "../styles/AuthenticationPage.scss";

const { Title, Text } = Typography;

export default function AuthenticationPage({ display }) {
  const [clientLogo, setClientLogo] = useState("");
  const [clientName, setClientName] = useState("");
  const { clientInfo } = useApplicationContext();

  useEffect(() => {
    if (!clientInfo) return;
    setClientLogo(<img src={clientInfo.logo_uri} alt="client logo" />);
    setClientName(clientInfo.name);
  }, [clientInfo]);

  const defaultSignInMessage = "Please sign in to continue";
  const signInMessage = `You are signing into ${clientName}`;

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
        <AuthenticationForm />
      </Card>
    </FlexContainer>
  );
}
