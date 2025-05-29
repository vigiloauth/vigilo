import { Card } from "antd";
import FlexContainer from "../components/FlexContainer";
import ConsentForm from "../forms/ConsentForm";
import ConsentPopup from "../popups/ConsentPopup";
import "../styles/ConsentPage.scss";
import { useApplicationContext } from "../context/ApplicationContext";
import { useEffect, useState } from "react";

export default function ConsentPage({ display }) {
  const [policyURI, setPolicyURI] = useState("");
  const { clientInfo } = useApplicationContext();

  useEffect(() => {
    if (!clientInfo || !clientInfo.policy_uri) return;
    setPolicyURI(clientInfo.policy_uri);
  }, [clientInfo]);

  return display === "popup" ? (
    <ConsentPopup policyURI={policyURI} />
  ) : (
    <FlexContainer className="consent-form-container">
      <Card className="consent-card" variant="borderless">
        {<ConsentForm policyURI={policyURI} />}
      </Card>
    </FlexContainer>
  );
}
