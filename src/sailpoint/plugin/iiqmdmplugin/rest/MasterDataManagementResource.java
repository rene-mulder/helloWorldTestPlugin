package sailpoint.plugin.iiqmdmplugin.rest;

import java.util.*;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import sailpoint.api.SailPointContext;
import sailpoint.object.Attributes;
import sailpoint.object.Capability;
import sailpoint.object.Custom;
import sailpoint.object.Identity;
import sailpoint.plugin.common.PluginRegistry;
import sailpoint.plugin.rest.jaxrs.AllowAll;
import sailpoint.rest.BaseResource;
import sailpoint.tools.GeneralException;
import sailpoint.plugin.iiqmdmplugin.MasterDataManagementDTO;
import sailpoint.plugin.rest.AbstractPluginRestResource;
import sailpoint.plugin.rest.jaxrs.SPRightsRequired;
import sailpoint.web.plugin.config.Plugin;
import sailpoint.plugin.iiqmdmplugin.MasterDataManagementPluginException;

/**
 * @author Menno Pieters
 */

@SPRightsRequired(value = { "MasterDataManagementPluginRestServiceAllow" })
@Path("iiqmdmplugin")
public class MasterDataManagementResource extends AbstractPluginRestResource {

	public final static String CONFIG_CUSTOM_OBJECT = "Master Data Manamenent Plugin Configuration";
	public final static String CONFIG_KEY_OBJECT_PERMISSIONS = "objectRights";
	public final static String CONFIG_PERMISSION_MANAGE = "MANAGE";
	public final static String CONFIG_PERMISSION_READ = "READ";
	public final static String CONFIG_PERMISSION_CREATE = "CREATE";
	public final static String CONFIG_PERMISSION_UPDATE = "UPDATE";
	public final static String CONFIG_PERMISSION_DELETE = "DELETE";
	public final static String[] CONFIG_PERMISSIONS = { CONFIG_PERMISSION_MANAGE, CONFIG_PERMISSION_CREATE, CONFIG_PERMISSION_DELETE, CONFIG_PERMISSION_READ, CONFIG_PERMISSION_UPDATE };

	private static Log log = LogFactory.getLog(MasterDataManagementResource.class);

	/**
	 * Default constructor.
	 * 
	 */
	public MasterDataManagementResource() {
		super();
	}

	/**
	 * Find and return the plugin configuraton settings Custom object.
	 * 
	 * @return Custom object containing the plugin configuration.
	 * @throws GeneralException 
	 */
	private Custom getPluginConfiguration() throws GeneralException {
		SailPointContext context = getContext();
		Custom config = context.getObjectByName(Custom.class, CONFIG_CUSTOM_OBJECT);
		if (config == null) {
			throw new MasterDataManagementPluginException("Configuration Custom Object not found for this plugin");
		}
		return config;
	}

	/**
	 * Verify the identity's access. The configuration object for the plugin is
	 * looked up. If found, permissions will be checked per Custom object to be
	 * managed. A system administrator will have full access.
	 * 
	 * @param identity
	 * @param objectName
	 * @param permission
	 * @return
	 * @throws GeneralException 
	 */
	@SuppressWarnings("unused")
	private boolean verifyAccess(Identity identity, String objectName, String permission) throws GeneralException {
		if (identity != null && objectName != null && permission != null) {
			if (Arrays.asList(CONFIG_PERMISSIONS).contains(permission)) {
				Custom config = getPluginConfiguration();
				if (config != null) {
					Identity.CapabilityManager cm = identity.getCapabilityManager();
					Collection<String> identityRights = cm.getEffectiveFlattenedRights();

					// Check SystemAdministrator
					if (cm.hasCapability(Capability.SYSTEM_ADMINISTRATOR)) {
						log.info("System administrator rights found. Granting permission");
						return true;
					}

					// Try other permissions
					Attributes<String, Object> attributes = config.getAttributes();
					if (attributes != null) {
						Map<String, Object> authorizations = (Map<String, Object>) attributes.get(CONFIG_KEY_OBJECT_PERMISSIONS);
						if (authorizations != null) {
							Map<String, Object> objectRights = (Map<String, Object>) authorizations.get(objectName);
							if (objectRights != null) {
								String manageAccess = (String) objectRights.get(CONFIG_PERMISSION_MANAGE);
								String specificAccess = (String) objectRights.get(permission);
								if ((manageAccess != null && identityRights.contains(manageAccess)) || (specificAccess != null && identityRights.contains(specificAccess))) {
									log.info("Required rights found. Granting permission");
									return true;
								}
							}
						}
					}
				}
			}
		}
		// If all conditions fail, no access is given.
		return false;
	}
	

	/**
	 * Verify the identity's access. Will look up the identity and using that,
	 * call sibling method.
	 * 
	 * @param identityName
	 * @param objectName
	 * @param permission
	 * @return
	 * @throws GeneralException
	 */
	private boolean verifyAccess(String identityName, String objectName, String permission) throws GeneralException {
		return verifyAccess(getContext().getObjectByName(Identity.class, identityName), objectName, permission);
	}

	/**
	 * Verify the identity's access. Will look up the current identity name from
	 * the context and using that, call sibling method.
	 * 
	 * @param objectName
	 * @param permission
	 * @return
	 * @throws GeneralException
	 */
	private boolean verifyAccess(String objectName, String permission) throws GeneralException {
		return verifyAccess(getContext().getUserName(), objectName, permission);
	}

	/**
	 * Get the full context of a Custom object.
	 * @param objectName
	 * @return
	 * @throws GeneralException
	 */
	@GET
	@AllowAll
	@Path("getCustom/{name}")
	@Produces(MediaType.APPLICATION_JSON) 
	public String getCustom(@PathParam("name") String objectName) throws GeneralException {
		if (verifyAccess(objectName, CONFIG_PERMISSION_READ)) {
			Custom custom = getContext().getObjectByName(Custom.class, objectName);
			if (custom != null) {
				Attributes<String, Object> attributes = custom.getAttributes();
				if (attributes != null) {
					Map<String, Object> map = attributes.getMap();
					GsonBuilder gb = new GsonBuilder();
					Gson gson = gb.create();
					return gson.toJson(map);					
				}
			}
		}		
		return null;
	}
}
