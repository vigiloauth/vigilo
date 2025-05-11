import { Card, Typography } from "antd";
import FlexContainer from "../components/FlexContainer";
import Container from "../components/Container";
import "../styles/AuthenticationPage.scss";
import AuthenticationForm from "../forms/AuthenticationForm";
import AuthenticationPopup from "../popups/AuthenticationPopup";

const { Title, Text } = Typography;

export default function AuthenticationPage({ display }) {
  return display === "popup" ? (
    <AuthenticationPopup />
  ) : (
    <FlexContainer className="auth-container">
      <Card className="auth-card" variant="borderless">
        <Container className="auth-header">
          <Title>Welcome Back</Title>
          <Text className="subtitle" type="secondary">
            Please sign in to continue
          </Text>
        </Container>
        <AuthenticationForm />
      </Card>
    </FlexContainer>
  );
}
