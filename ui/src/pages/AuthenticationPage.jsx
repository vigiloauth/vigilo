import { useState, useEffect, useCallback } from "react";
import { Card, Typography, message } from "antd";
import FlexContainer from "../components/FlexContainer";
import Container from "../components/Container";
import "../styles/AuthenticationPage.scss";
import AuthenticationForm from "../forms/AuthenticationForm";
import AuthenticationPopup from "../popups/AuthenticationPopup";
import URL_PARAMS from "../constants/urlParams";
import { getClientByID } from "../api/clientApi";

const { Title, Text } = Typography;

export default function AuthenticationPage({ display }) {
  const [image, setImage] = useState("");

  const fetchClientMetadata = async () => {
    const urlParams = new URLSearchParams(window.location.search);
    const clientID = urlParams.get(URL_PARAMS.CLIENT_ID);

    try {
      const data = await getClientByID({ clientID });
      console.log(data);
      if (data.logo_uri) {
        setImage(<img src={data.logo_uri} alt="client logo" />);
      }
    } catch (err) {
      message.error(err.message);
    }
  };

  useEffect(() => {
    fetchClientMetadata();
  }, []);

  return display === "popup" ? (
    <AuthenticationPopup image={image} />
  ) : (
    <FlexContainer className="auth-container">
      <Card className="auth-card" variant="borderless">
        <Container className="auth-header">
          {image ? image : <Title>Welcome Back</Title>}
          <Text className="subtitle" type="secondary">
            Please sign in to continue
          </Text>
        </Container>
        <AuthenticationForm />
      </Card>
    </FlexContainer>
  );
}
