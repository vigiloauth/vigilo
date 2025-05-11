import { useState } from "react";
import { Modal, Typography } from "antd";
import "../styles/popup.scss";
import Container from "../components/Container";
import AuthenticationForm from "../forms/AuthenticationForm";
import URL_PARAMS from "../constants/urlParams";

const { Title, Text } = Typography;

export default function AuthenticationPopup() {
  const [visible, setVisible] = useState(true);

  const urlParams = new URLSearchParams(window.location.search);
  const redirectURI = urlParams.get(URL_PARAMS.REDIRECT_URI);

  const onCancel = () => {
    console.log(redirectURI);
    setVisible(false);
  };

  const afterClose = () => {
    if (redirectURI) {
      window.location.replace(redirectURI);
    }
  };

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
        <Title level={4}>Welcome Back</Title>
        <Text className="subtitle" type="secondary">
          Please sign in to continue
        </Text>
      </Container>
      <AuthenticationForm />
    </Modal>
  );
}
