import { useState } from "react";
import { Modal, Typography } from "antd";
import { useApplicationContext } from "../context/ApplicationContext";
import Container from "../components/Container";
import AuthenticationForm from "../forms/AuthenticationForm";
import "../styles/popup.scss";

const { Title, Text } = Typography;

export default function AuthenticationPopup({ clientLogo, clientName }) {
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
      <AuthenticationForm />
    </Modal>
  );
}
