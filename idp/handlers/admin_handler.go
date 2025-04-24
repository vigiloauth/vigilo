package handlers

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/vigiloauth/vigilo/idp/config"
	domain "github.com/vigiloauth/vigilo/internal/domain/audit"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
	"github.com/vigiloauth/vigilo/internal/web"
)

type AdminHandler struct {
	auditLogger domain.AuditLogger
	logger      *config.Logger
	module      string
}

func NewAdminHandler(auditLogger domain.AuditLogger) *AdminHandler {
	return &AdminHandler{
		auditLogger: auditLogger,
		logger:      config.GetServerConfig().Logger(),
		module:      "Admin Handler",
	}
}

func (h *AdminHandler) GetAuditEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[GetAuditEvents]: Processing request")
	query := r.URL.Query()

	limit, err := strconv.Atoi(query.Get("limit"))
	if err != nil {
		limit = 100
	}

	offset, err := strconv.Atoi(query.Get("offset"))
	if err != nil {
		offset = 0
	}

	filters := h.buildFilters(w, query)
	fromStr := query.Get("from")
	toStr := query.Get("to")

	events, err := h.auditLogger.GetAuditEvents(ctx, filters, fromStr, toStr, limit, offset)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to retrieve audit events")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, events)
}

func (h *AdminHandler) buildFilters(w http.ResponseWriter, query url.Values) map[string]any {
	filters := make(map[string]any)
	if userID := query.Get("UserID"); userID != "" {
		filters["UserID"] = userID
	}
	if eventType := query.Get("EventType"); eventType != "" {
		filters["EventType"] = eventType
	}
	if successStr := query.Get("Success"); successStr != "" {
		success, err := strconv.ParseBool(successStr)
		if err != nil {
			web.WriteError(w, errors.New(errors.ErrCodeInvalidInput, "invalid 'Success' boolean"))
			return nil
		}
		filters["Success"] = success
	}
	if ip := query.Get("IP"); ip != "" {
		filters["IP"] = ip
	}
	if requestID := query.Get("RequestID"); requestID != "" {
		filters["RequestID"] = requestID
	}
	if sessionID := query.Get("SessionID"); sessionID != "" {
		filters["SessionID"] = sessionID
	}

	return filters
}
