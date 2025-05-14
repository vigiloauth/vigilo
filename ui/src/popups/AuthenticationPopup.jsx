import { useState } from "react";
import { Modal, Typography, Spin } from "antd";
import { useApplicationContext } from "../context/ApplicationContext";
import Container from "../components/Container";
import AuthenticationForm from "../forms/AuthenticationForm";
import FlexContainer from "../components/FlexContainer";
import "../styles/popup.scss";

const { Title, Text } = Typography;

export default function AuthenticationPopup({
  clientLogo,
  clientName,
  policyURI,
  loading,
}) {
  const [visible, setVisible] = useState(true);
  const { redirectURI } = useApplicationContext();

  const onCancel = () => {
    setVisible(false);
  };

  const afterClose = () => {
    if (redirectURI) {
      window.location.replace(redirectURI);
    }
  };

  const defaultSignInMessage = "Please sign in to continue";
  const signInMessage = `You are signing into ${clientName}`;

  if (loading) {
    return (
      <FlexContainer className="auth-container">
        <Spin size="large" tip="Loading..." />
      </FlexContainer>
    );
  }

  return (
    <Modal
      open={visible}
      onCancel={onCancel}
      width={450}
      maskClosable={true}
      className="custom-popup"
      afterClose={afterClose}
      footer={null}
      centered
    >
      <Container className="popup-header">
        {clientLogo ? clientLogo : <Title>Welcome Back</Title>}
        <Text className="subtitle" type="secondary">
          {clientName ? signInMessage : defaultSignInMessage}
        </Text>
      </Container>
      <AuthenticationForm policyURI={policyURI} />
    </Modal>
  );
}
